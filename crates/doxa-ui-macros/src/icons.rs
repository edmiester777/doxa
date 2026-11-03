//! Icon enums. `#[icons]` reads one SVG file per variant into `view!` nodes at compile time;
//! `#[react(module = …)]` on an enum makes each variant an island of the export it names.

use std::path::{Path, PathBuf};

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{Fields, Ident, ItemEnum, LitStr, Type};

use crate::react;

/// A unit variant, and the name its own attribute gives it (`export = …` or `file = …`).
struct Variant {
    ident: Ident,
    rename: Option<LitStr>,
}

/// Strip `#[attr(key = "…")]` from each variant, refusing anything but unit variants.
fn variants(item: &mut ItemEnum, attr: &str, key: &str) -> syn::Result<Vec<Variant>> {
    if !item.generics.params.is_empty() {
        return Err(syn::Error::new(
            item.generics.span(),
            "an icon enum can't be generic",
        ));
    }
    let mut out = Vec::new();
    for v in item.variants.iter_mut() {
        if !matches!(v.fields, Fields::Unit) || v.discriminant.is_some() {
            return Err(syn::Error::new(
                v.span(),
                "each variant of an icon enum is a plain name, like `ChevronDown`",
            ));
        }
        let mut rename = None;
        let mut kept = Vec::new();
        for a in v.attrs.drain(..) {
            if !a.path().is_ident(attr) {
                kept.push(a);
                continue;
            }
            a.parse_nested_meta(|m| {
                if m.path.is_ident(key) {
                    rename = Some(m.value()?.parse::<LitStr>()?);
                    Ok(())
                } else {
                    Err(m.error(format!("expected `{key} = \"…\"`")))
                }
            })?;
        }
        v.attrs = kept;
        out.push(Variant {
            ident: v.ident.clone(),
            rename,
        });
    }
    if out.is_empty() {
        return Err(syn::Error::new(
            item.ident.span(),
            "an icon enum needs at least one variant",
        ));
    }
    Ok(out)
}

/// Add the derives an `IconSet` needs that the enum doesn't already list.
fn derive_missing(item: &mut ItemEnum) {
    let mut have = Vec::new();
    for a in item.attrs.iter().filter(|a| a.path().is_ident("derive")) {
        let _ = a.parse_nested_meta(|m| {
            if let Some(last) = m.path.segments.last() {
                have.push(last.ident.to_string());
            }
            Ok(())
        });
    }
    let missing = ["Clone", "Copy", "Debug", "PartialEq", "Eq", "Hash"]
        .into_iter()
        .filter(|d| !have.iter().any(|h| h == d))
        .map(|d| format_ident!("{d}"));
    let missing: Vec<_> = missing.collect();
    if !missing.is_empty() {
        item.attrs.push(syn::parse_quote!(#[derive(#(#missing),*)]));
    }
}

/// `#[react(module = "lucide-react", props = IconProps)] enum Lucide { Plus, … }`.
pub(crate) fn expand_react(args: react::Args, mut item: ItemEnum) -> syn::Result<TokenStream> {
    if let Some(export) = &args.export {
        return Err(syn::Error::new(
            export.span(),
            "each variant is the export of its own name; rename one with `#[react(export = \"…\")]` on it",
        ));
    }
    if let Some(handle) = &args.handle {
        return Err(syn::Error::new(
            handle.span(),
            "`handle` is for one component; an icon enum has no `ref`",
        ));
    }
    let list = variants(&mut item, "react", "export")?;
    derive_missing(&mut item);
    let module = react::specifier(&args.module)?;
    let tracked = react::tracked(&args.module, &module)?;
    let props: Type = args
        .props
        .clone()
        .unwrap_or_else(|| syn::parse_quote!(::doxa::ui::IconProps));
    let name = &item.ident;
    let lazy = args.lazy;
    let mode = if lazy { "lazy" } else { "eager" };

    let mut parts = Vec::new();
    let mut arms = Vec::new();
    for v in &list {
        let export = match &v.rename {
            Some(e) => {
                react::check_export(e)?;
                e.value()
            }
            None => v.ident.to_string(),
        };
        let ident = &v.ident;
        let island = format!("{name}::{ident}");
        let spec = format!("doxa-react:{mode}:{export}:{module}");
        let (wrap, comp, load) = (
            format_ident!("__{}Props", ident),
            format_ident!("__{}", ident),
            format_ident!("__load_{}", ident),
        );
        parts.push(quote! {
            #[cfg(target_arch = "wasm32")]
            #[wasm_bindgen::prelude::wasm_bindgen(module = #spec, wasm_bindgen = ::doxa::ui::__private::wasm_bindgen)]
            extern "C" {
                #[wasm_bindgen(js_name = load)]
                fn #load() -> wasm_bindgen::JsValue;
            }

            #[derive(Clone)]
            struct #wrap(#props);

            impl ::doxa::ui::react::IslandProps for #wrap {
                const ISLAND: ::doxa::ui::react::Island = ::doxa::ui::react::Island {
                    name: #island,
                    module: #module,
                    export: #export,
                    lazy: #lazy,
                    #[cfg(target_arch = "wasm32")]
                    load: #load,
                };

                fn same_data(&self, other: &Self) -> bool {
                    self.0 == other.0
                }

                fn data(&self, out: &mut ::doxa::ui::react::Data) {
                    out.spread(&self.0)
                }

                fn events(&self, _: &mut ::doxa::ui::react::Events) {}
            }

            struct #comp;

            impl ::doxa::ui::Component for #comp {
                type Props = #wrap;
                const NAME: &'static str = #island;

                fn render(props: #wrap) -> ::doxa::ui::RenderFuture {
                    ::doxa::ui::react::render(props)
                }
            }
        });
        arms.push(quote! {
            #name::#ident => ::doxa::ui::IntoView::into_view(::doxa::ui::comp::<#comp>(#wrap(props))),
        });
    }

    Ok(quote! {
        #item

        #[allow(non_camel_case_types, non_snake_case)]
        const _: () = {
            #[cfg(target_arch = "wasm32")]
            use ::doxa::ui::__private::wasm_bindgen;
            #(const _: &[u8] = ::core::include_bytes!(#tracked);)*

            #(#parts)*

            impl ::doxa::ui::IconSet for #name {
                type Props = #props;

                fn render(self, props: #props) -> ::doxa::ui::View {
                    match self { #(#arms)* }
                }
            }

            impl ::doxa::ui::IntoView for #name {
                fn into_view(self) -> ::doxa::ui::View {
                    ::doxa::ui::IconSet::render(self, ::core::default::Default::default())
                }
            }
        };
    })
}

pub(crate) struct Args {
    npm: Option<LitStr>,
    dir: LitStr,
    case: Case,
}

#[derive(Clone, Copy)]
enum Case {
    Kebab,
    Snake,
    Pascal,
    Camel,
}

impl syn::parse::Parse for Args {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let (mut npm, mut dir, mut case) = (None, None, Case::Kebab);
        let start = input.span();
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<syn::Token![=]>()?;
            let value: LitStr = input.parse()?;
            match key.to_string().as_str() {
                "npm" => npm = Some(value),
                "dir" => dir = Some(value),
                "case" => {
                    case = match value.value().as_str() {
                        "kebab" => Case::Kebab,
                        "snake" => Case::Snake,
                        "pascal" => Case::Pascal,
                        "camel" => Case::Camel,
                        _ => {
                            return Err(syn::Error::new(
                                value.span(),
                                "`case` is `kebab`, `snake`, `pascal` or `camel`",
                            ))
                        }
                    }
                }
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!("unknown option `{other}`; expected `npm`, `dir` or `case`"),
                    ))
                }
            }
            if !input.is_empty() {
                input.parse::<syn::Token![,]>()?;
            }
        }
        let dir = dir.ok_or_else(|| {
            syn::Error::new(
                start,
                "`#[icons]` needs `dir = \"…\"`: `#[icons(npm = \"lucide-static\", dir = \"icons\")]` or `#[icons(dir = \"./assets/icons\")]`",
            )
        })?;
        Ok(Args { npm, dir, case })
    }
}

/// `ChevronDown` → `chevron-down`; a run of digits is a word, so `Trash2` → `trash-2`.
fn file_name(ident: &str, case: Case) -> String {
    let chars: Vec<char> = ident.chars().collect();
    let mut words: Vec<String> = Vec::new();
    for (i, &c) in chars.iter().enumerate() {
        let prev = i.checked_sub(1).map(|p| chars[p]);
        let next = chars.get(i + 1);
        let starts = match prev {
            None => true,
            Some(p) => {
                (c.is_uppercase() && (p.is_lowercase() || p.is_ascii_digit()))
                    || (c.is_uppercase()
                        && p.is_uppercase()
                        && next.is_some_and(|n| n.is_lowercase()))
                    || (c.is_ascii_digit() && !p.is_ascii_digit())
                    || (!c.is_ascii_digit() && p.is_ascii_digit())
            }
        };
        if c == '_' {
            words.push(String::new());
            continue;
        }
        if starts || words.is_empty() {
            words.push(String::new());
        }
        words.last_mut().expect("a word").push(c);
    }
    let words: Vec<String> = words
        .into_iter()
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect();
    let title = |w: &String| {
        let mut c = w.chars();
        c.next()
            .map(|f| f.to_uppercase().chain(c).collect::<String>())
            .unwrap_or_default()
    };
    match case {
        Case::Kebab => words.join("-"),
        Case::Snake => words.join("_"),
        Case::Pascal => words.iter().map(title).collect(),
        Case::Camel => words
            .iter()
            .enumerate()
            .map(|(i, w)| if i == 0 { w.clone() } else { title(w) })
            .collect(),
    }
}

/// Where `package` is installed: `DOXA_NODE_MODULES`, else a `node_modules` (or `doxa build`'s
/// `target/doxa/js/node_modules`) at or above the crate.
fn installed(package: &str, env: Option<PathBuf>, crate_dir: &Path) -> Option<PathBuf> {
    if let Some(root) = env {
        return Some(root.join(package)).filter(|p| p.is_dir());
    }
    crate_dir.ancestors().find_map(|at| {
        [
            at.join("node_modules"),
            at.join("target/doxa/js/node_modules"),
        ]
        .into_iter()
        .map(|root| root.join(package))
        .find(|p| p.is_dir())
    })
}

/// `#[icons(npm = "lucide-static", dir = "icons", case = "kebab")] enum Icon { Plus, … }`.
pub(crate) fn expand_icons(args: Args, mut item: ItemEnum) -> syn::Result<TokenStream> {
    let list = variants(&mut item, "icons", "file")?;
    derive_missing(&mut item);
    let crate_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let mut tracked = Vec::new();
    let base = match &args.npm {
        Some(npm) => {
            let package = npm.value();
            tracked = react::tracked(npm, &package)?;
            let env = std::env::var_os("DOXA_NODE_MODULES").map(PathBuf::from);
            let root = installed(&package, env, &crate_dir).ok_or_else(|| {
                syn::Error::new(
                    npm.span(),
                    format!(
                        "`{package}` isn't installed in node_modules; run `doxa build` once to install it"
                    ),
                )
            })?;
            root.join(args.dir.value())
        }
        None => crate_dir.join(args.dir.value().trim_start_matches("./")),
    };
    let name = &item.ident;
    let mut arms = Vec::new();
    for v in &list {
        let file = match &v.rename {
            Some(f) => f.value(),
            None => file_name(&v.ident.to_string(), args.case),
        };
        let path = base.join(format!("{file}.svg"));
        let svg = std::fs::read_to_string(&path).map_err(|_| {
            syn::Error::new(
                v.ident.span(),
                format!(
                    "no icon `{}`: `{}` doesn't exist; name the file with `#[icons(file = \"…\")]`",
                    v.ident,
                    path.display()
                ),
            )
        })?;
        let (attrs, body) = svg_tokens(&svg, v.ident.span(), &path)?;
        tracked.push(path.to_string_lossy().into_owned());
        let ident = &v.ident;
        arms.push(quote! {
            #name::#ident => ::doxa::ui::__private::svg_root(&[#attrs], #body, &props),
        });
    }

    Ok(quote! {
        #item

        const _: () = {
            #(const _: &[u8] = ::core::include_bytes!(#tracked);)*

            impl ::doxa::ui::IconSet for #name {
                type Props = ::doxa::ui::IconProps;

                fn render(self, props: ::doxa::ui::IconProps) -> ::doxa::ui::View {
                    match self { #(#arms)* }
                }
            }

            impl ::doxa::ui::IntoView for #name {
                fn into_view(self) -> ::doxa::ui::View {
                    ::doxa::ui::IconSet::render(self, ::core::default::Default::default())
                }
            }
        };
    })
}

/// The root `<svg>`'s attributes, and its children as one `View` expression.
fn svg_tokens(svg: &str, at: Span, path: &Path) -> syn::Result<(TokenStream, TokenStream)> {
    let fail = |why: String| syn::Error::new(at, format!("`{}`: {why}", path.display()));
    let doc = roxmltree::Document::parse(svg).map_err(|e| fail(e.to_string()))?;
    let root = doc.root_element();
    if root.tag_name().name() != "svg" {
        return Err(fail(format!(
            "the root is `<{}>`, not `<svg>`",
            root.tag_name().name()
        )));
    }
    let attrs = attributes(root, &fail)?
        .into_iter()
        .map(|(k, v)| quote!((#k, #v),));
    let body = children(root, &fail)?;
    Ok((quote!(#(#attrs)*), body))
}

fn attributes(
    node: roxmltree::Node,
    fail: &dyn Fn(String) -> syn::Error,
) -> syn::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for a in node.attributes() {
        if a.namespace().is_some() {
            return Err(fail(format!(
                "attribute `{}` on `<{}>` has a namespace, which icons don't support",
                a.name(),
                node.tag_name().name()
            )));
        }
        out.push((a.name().to_owned(), a.value().to_owned()));
    }
    Ok(out)
}

fn children(
    node: roxmltree::Node,
    fail: &dyn Fn(String) -> syn::Error,
) -> syn::Result<TokenStream> {
    let mut kids = Vec::new();
    for c in node.children() {
        if c.is_element() {
            let tag = c.tag_name().name();
            let attrs = attributes(c, fail)?
                .into_iter()
                .map(|(k, v)| quote!(.attr(#k, #v)));
            let inner = children(c, fail)?;
            kids.push(quote! {
                ::doxa::ui::IntoView::into_view(
                    ::doxa::ui::__private::svg_el(#tag) #(#attrs)* .child(#inner)
                )
            });
        } else if let Some(text) = c.text().map(str::trim).filter(|t| !t.is_empty()) {
            if c.is_text() {
                kids.push(quote!(::doxa::ui::IntoView::into_view(#text)));
            }
        }
    }
    Ok(quote! {
        <::doxa::ui::View as ::core::iter::FromIterator<::doxa::ui::View>>::from_iter([#(#kids),*])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_name_their_files() {
        assert_eq!(file_name("ChevronDown", Case::Kebab), "chevron-down");
        assert_eq!(file_name("Trash2", Case::Kebab), "trash-2");
        assert_eq!(file_name("HTMLFile", Case::Kebab), "html-file");
        assert_eq!(file_name("ChevronDown", Case::Snake), "chevron_down");
        assert_eq!(file_name("ChevronDown", Case::Camel), "chevronDown");
        assert_eq!(file_name("ChevronDown", Case::Pascal), "ChevronDown");
    }

    #[test]
    fn a_package_is_found_above_the_crate_or_under_doxa_builds_install() {
        let dir = std::env::temp_dir().join(format!("doxa-icons-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let web = dir.join("web");
        std::fs::create_dir_all(dir.join("target/doxa/js/node_modules/lucide-static")).unwrap();
        std::fs::create_dir_all(&web).unwrap();
        assert_eq!(
            installed("lucide-static", None, &web),
            Some(dir.join("target/doxa/js/node_modules/lucide-static"))
        );
        assert_eq!(installed("missing", None, &web), None);
        let env = dir.join("target/doxa/js/node_modules");
        assert!(installed("lucide-static", Some(env), Path::new("/")).is_some());
    }

    #[test]
    fn an_svg_becomes_its_root_attributes_and_child_nodes() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" width="24" class="i"><path d="M5 12h14"/><g><circle r="2"/></g></svg>"#;
        let (attrs, body) = svg_tokens(svg, Span::call_site(), Path::new("plus.svg")).unwrap();
        let (attrs, body) = (attrs.to_string(), body.to_string());
        assert!(attrs.contains("\"width\" , \"24\""), "{attrs}");
        assert!(!attrs.contains("xmlns"), "{attrs}");
        assert!(
            body.contains("svg_el (\"path\") . attr (\"d\" , \"M5 12h14\")"),
            "{body}"
        );
        assert!(body.contains("svg_el (\"circle\")"), "{body}");
        let err = svg_tokens("<div/>", Span::call_site(), Path::new("x.svg")).unwrap_err();
        assert!(err.to_string().contains("not `<svg>`"), "{err}");
    }
}
