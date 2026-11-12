//! Icon enums. `#[icons]` resolves one SVG per variant through esbuild into `view!` nodes;
//! `#[react(module = …)]` on an enum makes each variant an island of the export it names.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

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
    from: LitStr,
    template: Template,
}

/// `from` split around its one `{case}` placeholder.
#[derive(Debug, PartialEq)]
struct Template {
    before: String,
    case: Case,
    after: String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Case {
    Kebab,
    Snake,
    Pascal,
    Camel,
}

impl Template {
    fn parse(from: &str) -> Result<Self, String> {
        let cases = [
            ("{kebab}", Case::Kebab),
            ("{snake}", Case::Snake),
            ("{pascal}", Case::Pascal),
            ("{camel}", Case::Camel),
        ];
        let mut found = cases
            .iter()
            .flat_map(|&(p, case)| from.match_indices(p).map(move |(at, _)| (at, p, case)));
        let (at, placeholder, case) = found.next().ok_or_else(|| {
            format!("`from` names each variant's file with `{{kebab}}`, `{{snake}}`, `{{pascal}}` or `{{camel}}`, as in `\"lucide-static/icons/{{kebab}}.svg\"`; `{from}` has none")
        })?;
        if found.next().is_some() {
            return Err(format!("`{from}` has more than one placeholder"));
        }
        Ok(Template {
            before: from[..at].to_owned(),
            case,
            after: from[at + placeholder.len()..].to_owned(),
        })
    }

    fn specifier(&self, name: &str) -> String {
        format!("{}{name}{}", self.before, self.after)
    }
}

impl syn::parse::Parse for Args {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let start = input.span();
        let mut from = None;
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<syn::Token![=]>()?;
            let value: LitStr = input.parse()?;
            if key != "from" {
                return Err(syn::Error::new(
                    key.span(),
                    format!("unknown option `{key}`; expected `from = \"…\"`"),
                ));
            }
            from = Some(value);
            if !input.is_empty() {
                input.parse::<syn::Token![,]>()?;
            }
        }
        let from = from.ok_or_else(|| {
            syn::Error::new(
                start,
                "`#[icons]` needs `from = \"…\"`: `#[icons(from = \"lucide-static/icons/{kebab}.svg\")]` or `#[icons(from = \"./assets/icons/{kebab}.svg\")]`",
            )
        })?;
        let template =
            Template::parse(&from.value()).map_err(|e| syn::Error::new(from.span(), e))?;
        Ok(Args { from, template })
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
                    // `Grid3x3` is `grid-3x3`: a word that began with a digit keeps its digits.
                    || (c.is_ascii_digit()
                        && !p.is_ascii_digit()
                        && !words
                            .last()
                            .and_then(|w| w.chars().next())
                            .is_some_and(|f| f.is_ascii_digit()))
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

/// `doxa build`'s npm install (`DOXA_NODE_MODULES`, else `target/doxa/js/node_modules` at or
/// above the crate), which esbuild searches after the `node_modules` above the crate.
fn node_path(env: Option<PathBuf>, crate_dir: &Path) -> Option<PathBuf> {
    env.or_else(|| {
        crate_dir
            .ancestors()
            .map(|at| at.join("target/doxa/js/node_modules"))
            .find(|p| p.is_dir())
    })
}

enum Resolved {
    /// One file per specifier, in order.
    Files(Vec<PathBuf>),
    /// The specifiers esbuild couldn't resolve.
    Missing(Vec<String>),
}

/// Resolve each specifier from `crate_dir` the way the bundle does.
fn resolve(specs: &[String], crate_dir: &Path) -> Result<Resolved, String> {
    static RUN: AtomicUsize = AtomicUsize::new(0);
    let esbuild = doxa_build::tool::esbuild().map_err(|e| e.to_string())?;
    let tmp = std::env::temp_dir().join(format!(
        "doxa-icons-{}-{}",
        std::process::id(),
        RUN.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    let meta = tmp.join("meta.json");
    let mut cmd = Command::new(&esbuild);
    // Read from stdin, imports resolve from the working directory.
    cmd.current_dir(crate_dir)
        .args([
            "--bundle",
            "--loader:.svg=empty",
            "--log-level=error",
            "--log-limit=0",
            "--color=false",
        ])
        .arg(format!("--outfile={}", tmp.join("out.js").display()))
        .arg(format!("--metafile={}", meta.display()))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(dir) = node_path(
        std::env::var_os("DOXA_NODE_MODULES").map(PathBuf::from),
        crate_dir,
    ) {
        cmd.env("NODE_PATH", dir);
    }
    let mut run = || -> Result<_, String> {
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("couldn't start `{}`: {e}", esbuild.display()))?;
        let entry: String = specs
            .iter()
            .map(|s| format!("import {};\n", serde_json::Value::from(s.as_str())))
            .collect();
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(entry.as_bytes())
            .map_err(|e| e.to_string())?;
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        if !out.status.success() {
            let missing = unresolved(&stderr);
            if missing.is_empty() {
                return Err(format!("esbuild failed:\n{stderr}"));
            }
            return Ok(Resolved::Missing(missing));
        }
        let json =
            std::fs::read_to_string(&meta).map_err(|e| format!("{}: {e}", meta.display()))?;
        let found = imports(&json)?;
        specs
            .iter()
            .map(|s| match found.iter().find(|(o, _)| o == s) {
                Some((_, p)) => Ok(crate_dir.join(p)),
                None => Err(format!("esbuild's metafile has no import of `{s}`")),
            })
            .collect::<Result<_, _>>()
            .map(Resolved::Files)
    };
    let result = run();
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

/// The specifiers in esbuild's `Could not resolve "…"` errors.
fn unresolved(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter_map(|l| l.split_once("Could not resolve \"")?.1.split_once('"'))
        .map(|(spec, _)| spec.to_owned())
        .collect()
}

/// Each stdin import's specifier and the path it resolved to, relative to the working directory.
fn imports(metafile: &str) -> Result<Vec<(String, String)>, String> {
    let meta: serde_json::Value =
        serde_json::from_str(metafile).map_err(|e| format!("bad esbuild metafile: {e}"))?;
    let list = meta["inputs"]["<stdin>"]["imports"]
        .as_array()
        .ok_or("esbuild's metafile lists no imports")?;
    Ok(list
        .iter()
        .filter_map(|i| {
            Some((
                i["original"].as_str()?.to_owned(),
                i["path"].as_str()?.to_owned(),
            ))
        })
        .collect())
}

/// `#[icons(from = "lucide-static/icons/{kebab}.svg")] enum Icon { Plus, … }`.
pub(crate) fn expand_icons(args: Args, mut item: ItemEnum) -> syn::Result<TokenStream> {
    let list = variants(&mut item, "icons", "file")?;
    derive_missing(&mut item);
    let crate_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let specs: Vec<String> = list
        .iter()
        .map(|v| {
            let file = match &v.rename {
                Some(f) => f.value(),
                None => file_name(&v.ident.to_string(), args.template.case),
            };
            args.template.specifier(&file)
        })
        .collect();
    let mut tracked = match specs[0].starts_with(['.', '/']) {
        true => Vec::new(),
        false => react::tracked(&args.from, &specs[0])?,
    };
    let files = match resolve(&specs, &crate_dir)
        .map_err(|e| syn::Error::new(args.from.span(), e))?
    {
        Resolved::Files(files) => files,
        Resolved::Missing(missing) => {
            let mut errors = list.iter().zip(&specs).filter(|(_, s)| missing.contains(s)).map(|(v, s)| {
                syn::Error::new(
                    v.ident.span(),
                    format!("no icon `{}`: `{s}` doesn't resolve; name its file with `#[icons(file = \"…\")]`", v.ident),
                )
            });
            let mut first = errors.next().unwrap_or_else(|| {
                syn::Error::new(
                    args.from.span(),
                    format!("esbuild couldn't resolve {missing:?}"),
                )
            });
            errors.for_each(|e| first.combine(e));
            return Err(first);
        }
    };
    let name = &item.ident;
    let mut arms = Vec::new();
    for (v, path) in list.iter().zip(files) {
        let svg = std::fs::read_to_string(&path)
            .map_err(|e| syn::Error::new(v.ident.span(), format!("`{}`: {e}", path.display())))?;
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
        let name = a.name().to_ascii_lowercase();
        let value: String = a
            .value()
            .chars()
            .filter(|c| !c.is_whitespace() && !c.is_control())
            .collect::<String>()
            .to_ascii_lowercase();
        let scripted_url = ["javascript:", "vbscript:", "data:"]
            .iter()
            .any(|s| value.starts_with(s));
        if name.starts_with("on") || (name == "href" && scripted_url) {
            return Err(fail(format!(
                "attribute `{}` on `<{}>` runs script, which an inlined icon must not",
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
            if matches!(
                tag.to_ascii_lowercase().as_str(),
                "script" | "foreignobject"
            ) {
                return Err(fail(format!(
                    "`<{tag}>` can run script or hold HTML, which an inlined icon must not"
                )));
            }
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
        assert_eq!(file_name("Move3d", Case::Kebab), "move-3d");
        assert_eq!(file_name("Grid3x3", Case::Kebab), "grid-3x3");
        assert_eq!(file_name("HTMLFile", Case::Kebab), "html-file");
        assert_eq!(file_name("ChevronDown", Case::Snake), "chevron_down");
        assert_eq!(file_name("ChevronDown", Case::Camel), "chevronDown");
        assert_eq!(file_name("ChevronDown", Case::Pascal), "ChevronDown");
    }

    #[test]
    fn from_splits_around_its_one_placeholder() {
        let t = Template::parse("lucide-static/icons/{kebab}.svg").unwrap();
        assert_eq!(t.case, Case::Kebab);
        assert_eq!(t.specifier("trash-2"), "lucide-static/icons/trash-2.svg");
        assert!(Template::parse("icons/plus.svg")
            .unwrap_err()
            .contains("has none"));
        assert!(Template::parse("{kebab}/{snake}.svg")
            .unwrap_err()
            .contains("more than one"));
    }

    #[test]
    fn doxa_builds_install_is_found_above_the_crate() {
        let dir = std::env::temp_dir().join(format!("doxa-icons-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let web = dir.join("web");
        std::fs::create_dir_all(dir.join("target/doxa/js/node_modules")).unwrap();
        std::fs::create_dir_all(&web).unwrap();
        assert_eq!(
            node_path(None, &web),
            Some(dir.join("target/doxa/js/node_modules"))
        );
        let env = PathBuf::from("/elsewhere");
        assert_eq!(node_path(Some(env.clone()), &web), Some(env));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn esbuild_output_names_resolved_and_missing_imports() {
        let stderr =
            "✘ [ERROR] Could not resolve \"./assets/icons/nope.svg\"\n\n    <stdin>:2:7:\n";
        assert_eq!(unresolved(stderr), ["./assets/icons/nope.svg"]);
        let meta = r#"{"inputs":{"<stdin>":{"imports":[{"path":"assets/icons/plus.svg","kind":"import-statement","original":"./assets/icons/plus.svg"}]}}}"#;
        assert_eq!(
            imports(meta).unwrap(),
            [(
                "./assets/icons/plus.svg".to_owned(),
                "assets/icons/plus.svg".to_owned()
            )]
        );
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

    #[test]
    fn an_svg_that_runs_script_is_refused() {
        for svg in [
            r#"<svg onload="go()"><path/></svg>"#,
            r#"<svg><script>go()</script></svg>"#,
            r#"<svg><foreignObject><div/></foreignObject></svg>"#,
            r#"<svg><a href=" javascript:go()"><path/></a></svg>"#,
        ] {
            let err = svg_tokens(svg, Span::call_site(), Path::new("x.svg")).unwrap_err();
            assert!(err.to_string().contains("script"), "{svg}: {err}");
        }
    }
}
