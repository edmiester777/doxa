//! A shared source file as the browser build sees it, so an edit only the server compiles
//! skips the wasm rebuild.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::{Attribute, Item, Meta};

/// The last browser view seen of each file.
#[derive(Debug, Default)]
pub struct ClientViews(HashMap<PathBuf, u64>);

impl ClientViews {
    /// Views of every `.rs` file under `dirs`, outside `skip`.
    pub fn of(dirs: &[PathBuf], skip: &[PathBuf]) -> ClientViews {
        let mut views = ClientViews::default();
        let mut stack: Vec<PathBuf> = dirs.to_vec();
        while let Some(dir) = stack.pop() {
            if skip.iter().any(|s| dir.starts_with(s)) {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    if !p.ends_with("node_modules") && !p.ends_with(".git") {
                        stack.push(p);
                    }
                } else if p.extension().is_some_and(|x| x == "rs") {
                    views.unchanged(&p);
                }
            }
        }
        views
    }

    /// Whether `path`'s browser view is the one last seen; a file not seen before, or one that
    /// doesn't parse, has changed.
    pub fn unchanged(&mut self, path: &Path) -> bool {
        let view = std::fs::read_to_string(path)
            .ok()
            .and_then(|src| client_view(&src));
        let Some(view) = view else {
            self.0.remove(path);
            return false;
        };
        let mut h = DefaultHasher::new();
        view.hash(&mut h);
        self.0.insert(path.to_owned(), h.finish()) == Some(h.finish())
    }
}

/// `src` without route bodies and items only the server compiles.
fn client_view(src: &str) -> Option<String> {
    let mut file = syn::parse_file(src).ok()?;
    strip(&mut file.items);
    Some(file.into_token_stream().to_string())
}

fn strip(items: &mut Vec<Item>) {
    items.retain(|i| !attrs(i).iter().any(server_only));
    for item in items {
        match item {
            Item::Fn(f) if f.attrs.iter().any(is_route) => *f.block = syn::parse_quote!({}),
            Item::Mod(m) => {
                if let Some((_, inner)) = &mut m.content {
                    strip(inner);
                }
            }
            _ => {}
        }
    }
}

fn last_segment(attr: &Attribute) -> String {
    attr.path()
        .segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default()
}

fn is_route(attr: &Attribute) -> bool {
    ["get", "post", "put", "patch", "delete", "operation"].contains(&last_segment(attr).as_str())
}

/// `#[server]`, or `#[cfg(not(target_arch = "wasm32"))]`.
fn server_only(attr: &Attribute) -> bool {
    match &attr.meta {
        Meta::Path(_) => last_segment(attr) == "server",
        Meta::List(l) if l.path.is_ident("cfg") => {
            l.tokens.to_string().replace(' ', "") == "not(target_arch=\"wasm32\")"
        }
        _ => false,
    }
}

fn attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::ExternCrate(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::ForeignMod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::TraitAlias(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Union(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &str = r#"
        #[get("/w")]
        pub async fn w(State(s): State<S>) -> Json<u32> { Json(s.count()) }
    "#;

    #[test]
    fn a_route_body_and_server_items_are_not_the_browsers() {
        let base = client_view(ROUTE).unwrap();
        let body = ROUTE.replace("s.count()", "s.count() + 1");
        assert_eq!(client_view(&body).unwrap(), base);
        let server =
            format!("{ROUTE}\n#[server] impl From<A> for B {{ fn from(_: A) -> B {{ B }} }}");
        assert_eq!(client_view(&server).unwrap(), base);
        let gated = format!("{ROUTE}\n#[cfg(not(target_arch = \"wasm32\"))] fn helper() {{}}");
        assert_eq!(client_view(&gated).unwrap(), base);
    }

    #[test]
    fn a_signature_or_a_plain_function_is() {
        let base = client_view(ROUTE).unwrap();
        assert_ne!(
            client_view(&ROUTE.replace("Json<u32>", "Json<u64>")).unwrap(),
            base
        );
        let plain = format!("{ROUTE}\nfn shared() {{ 1; }}");
        assert_ne!(
            client_view(&plain).unwrap(),
            client_view(&plain.replace("1;", "2;")).unwrap()
        );
    }

    #[test]
    fn an_unseen_or_unparsable_file_has_changed() {
        let dir = std::env::temp_dir().join(format!("doxa-view-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("routes.rs");
        std::fs::write(&f, ROUTE).unwrap();
        let mut views = ClientViews::default();
        assert!(!views.unchanged(&f));
        std::fs::write(&f, ROUTE.replace("s.count()", "0")).unwrap();
        assert!(views.unchanged(&f));
        std::fs::write(&f, "fn (").unwrap();
        assert!(!views.unchanged(&f));
        let primed = ClientViews::of(std::slice::from_ref(&dir), &[]);
        assert_eq!(primed.0.len(), 0, "an unparsable file has no view");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
