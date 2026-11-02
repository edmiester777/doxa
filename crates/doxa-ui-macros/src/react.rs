//! `#[react]`: a props struct becomes a component rendering a React component as an island.

use proc_macro2::TokenStream;
use quote::{format_ident, quote, quote_spanned};
use syn::ext::IdentExt;
use syn::spanned::Spanned;
use syn::{Fields, Ident, ItemStruct, LitStr, Type};

use crate::component::{builder, Prop};

pub(crate) struct Args {
    module: LitStr,
    export: LitStr,
    lazy: bool,
}

impl syn::parse::Parse for Args {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let (mut module, mut export, mut lazy) = (None, None, false);
        let start = input.span();
        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            match ident.to_string().as_str() {
                "module" => {
                    input.parse::<syn::Token![=]>()?;
                    module = Some(input.parse::<LitStr>()?);
                }
                "export" => {
                    input.parse::<syn::Token![=]>()?;
                    export = Some(input.parse::<LitStr>()?);
                }
                "lazy" => lazy = true,
                other => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!("unknown option `{other}`; expected `module`, `export` or `lazy`"),
                    ))
                }
            }
            if !input.is_empty() {
                input.parse::<syn::Token![,]>()?;
            }
        }
        let missing = |what: &str| {
            syn::Error::new(
                start,
                format!("`#[react]` needs `{what} = \"…\"`, e.g. `#[react(module = \"@monaco-editor/react\", export = \"default\")]`"),
            )
        };
        let module = module.ok_or_else(|| missing("module"))?;
        let export = export.ok_or_else(|| missing("export"))?;
        let ident_like = |e: &str| {
            e.chars()
                .next()
                .is_some_and(|c| c.is_alphabetic() || c == '_' || c == '$')
                && e.chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
        };
        if !export.value().split('.').all(ident_like) {
            return Err(syn::Error::new(
                export.span(),
                "`export` is a JS name, `default`, or a dotted path like `Popover.Trigger`",
            ));
        }
        Ok(Args {
            module,
            export,
            lazy,
        })
    }
}

enum Role {
    Data,
    Optional,
    Event,
    /// A `View` or `Option<View>`, rendered by doxa into a host React places.
    Slot {
        optional: bool,
    },
    /// `#[react(element)]`: a `View` of one element, which React renders itself.
    Element,
    /// `#[react(func)]`: a `Func` or `AsyncFunc` React calls for a value.
    Func {
        is_async: bool,
    },
    /// `#[react(render)]`: a `Render` React places as an element.
    Render,
}

struct Field {
    name: Ident,
    ty: Type,
    js: String,
    role: Role,
}

/// `./ts/x.tsx` is under the web crate root; anything else is an npm specifier.
fn specifier(module: &LitStr) -> syn::Result<String> {
    let m = module.value();
    if let Some(rest) = m.strip_prefix("./") {
        Ok(format!("doxa-island:{rest}"))
    } else if m.starts_with("../") {
        Ok(format!("doxa-island:{m}"))
    } else if m.is_empty() || m.starts_with('/') {
        Err(syn::Error::new(
            module.span(),
            "`module` is an npm package, or a path like `./ts/editor.tsx` under the web crate",
        ))
    } else {
        Ok(m)
    }
}

fn camel(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut up = false;
    for c in name.chars() {
        if c == '_' {
            up = !out.is_empty();
        } else if up {
            out.extend(c.to_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// `Option<T>` where `T`'s last segment is `name`.
fn option_of(ty: &Type, name: &str) -> bool {
    let Type::Path(p) = ty else { return false };
    let Some(last) = p.path.segments.last() else {
        return false;
    };
    let syn::PathArguments::AngleBracketed(args) = &last.arguments else {
        return false;
    };
    last.ident == "Option"
        && matches!(args.args.first(), Some(syn::GenericArgument::Type(t)) if last_segment_is(t, name))
}

fn last_segment_is(ty: &Type, name: &str) -> bool {
    matches!(ty, Type::Path(p) if p.qself.is_none() && p.path.segments.last().is_some_and(|s| s.ident == name))
}

pub(crate) fn expand(args: Args, mut item: ItemStruct) -> syn::Result<TokenStream> {
    if !item.generics.params.is_empty() {
        return Err(syn::Error::new(
            item.generics.span(),
            "`#[react]` components can't be generic",
        ));
    }
    let Fields::Named(named) = &mut item.fields else {
        return Err(syn::Error::new(
            item.span(),
            "`#[react]` goes on a struct with named fields, one per prop",
        ));
    };
    let mut fields = Vec::new();
    for f in named.named.iter_mut() {
        let name = f.ident.clone().expect("named field");
        if name == "key" {
            return Err(syn::Error::new(
                name.span(),
                "`key` is reserved for list identity; rename the prop",
            ));
        }
        let (mut optional, mut event, mut element, mut rename) = (false, false, false, None);
        let (mut func, mut render) = (false, false);
        let mut kept = Vec::new();
        for attr in f.attrs.drain(..) {
            if !attr.path().is_ident("react") {
                kept.push(attr);
                continue;
            }
            attr.parse_nested_meta(|m| {
                if m.path.is_ident("optional") {
                    optional = true;
                } else if m.path.is_ident("event") {
                    event = true;
                } else if m.path.is_ident("element") {
                    element = true;
                } else if m.path.is_ident("func") {
                    func = true;
                } else if m.path.is_ident("render") {
                    render = true;
                } else if m.path.is_ident("rename") {
                    rename = Some(m.value()?.parse::<LitStr>()?.value());
                } else {
                    return Err(m.error(
                        "expected `optional`, `event`, `element`, `func`, `render` or `rename = \"…\"`",
                    ));
                }
                Ok(())
            })?;
        }
        f.attrs = kept;
        if [optional, event, element, func, render]
            .iter()
            .filter(|b| **b)
            .count()
            > 1
        {
            return Err(syn::Error::new(
                name.span(),
                "a prop takes one of `optional`, `event`, `element`, `func` and `render`",
            ));
        }
        if func && !last_segment_is(&f.ty, "Func") && !last_segment_is(&f.ty, "AsyncFunc") {
            return Err(syn::Error::new(
                f.ty.span(),
                format!(
                    "`#[react(func)]` field `{name}` must be a `Func<A, R>` or `AsyncFunc<A, R>`"
                ),
            ));
        }
        if render && !last_segment_is(&f.ty, "Render") {
            return Err(syn::Error::new(
                f.ty.span(),
                format!("`#[react(render)]` field `{name}` must be a `Render<A>`"),
            ));
        }
        if element && !last_segment_is(&f.ty, "View") {
            return Err(syn::Error::new(
                f.ty.span(),
                format!("`#[react(element)]` field `{name}` must be a `View`"),
            ));
        }
        let role = match (optional, event) {
            _ if element => Role::Element,
            _ if render => Role::Render,
            _ if func => Role::Func {
                is_async: last_segment_is(&f.ty, "AsyncFunc"),
            },
            (true, true) => unreachable!("two roles are refused above"),
            (true, false) if !last_segment_is(&f.ty, "Option") => {
                return Err(syn::Error::new(
                    f.ty.span(),
                    format!("`#[react(optional)]` field `{name}` must be an `Option<T>`"),
                ))
            }
            (true, false) => Role::Optional,
            (false, true) if !last_segment_is(&f.ty, "Callback") => {
                return Err(syn::Error::new(
                    f.ty.span(),
                    format!("`#[react(event)]` field `{name}` must be a `Callback<T>`"),
                ))
            }
            (false, true) => Role::Event,
            (false, false) if last_segment_is(&f.ty, "View") => Role::Slot { optional: false },
            (false, false) if option_of(&f.ty, "View") => Role::Slot { optional: true },
            (false, false) => Role::Data,
        };
        fields.push(Field {
            js: rename.unwrap_or_else(|| camel(&name.unraw().to_string())),
            name,
            ty: f.ty.clone(),
            role,
        });
    }

    let vis = &item.vis;
    let name = &item.ident;
    let name_str = name.to_string();
    let props_ty = format_ident!("{}Props", name);
    let module = specifier(&args.module)?;
    let mut tracked = Vec::new();
    if !module.starts_with("doxa-island:") {
        let dir = std::env::var_os("CARGO_MANIFEST_DIR").map(std::path::PathBuf::from);
        if let Some(declared) = dir.as_deref().and_then(crate::npm::declared) {
            crate::npm::check(&module, &declared)
                .map_err(|e| syn::Error::new(args.module.span(), e))?;
            tracked = declared.package_json;
        }
    }
    let tracked = tracked.iter().map(|p| p.to_string_lossy().into_owned());
    let export = args.export.value();
    let lazy = args.lazy;
    let spec = format!(
        "doxa-react:{}:{export}:{module}",
        if lazy { "lazy" } else { "eager" }
    );
    let bindings = format_ident!("__doxa_react_{}", name);

    let (docs, others): (Vec<_>, Vec<_>) =
        item.attrs.iter().partition(|a| a.path().is_ident("doc"));
    let struct_fields = named.named.iter();

    let props: Vec<Prop> = fields
        .iter()
        .map(|f| Prop {
            name: f.name.clone(),
            ty: f.ty.clone(),
            default: (f.name == "children"
                || matches!(f.role, Role::Optional | Role::Slot { optional: true })
                || (matches!(f.role, Role::Data) && last_segment_is(&f.ty, "Option")))
            .then(|| quote!(::core::default::Default::default())),
            optional: false,
        })
        .collect();
    let builder = builder(vis, name, &props_ty, &props);

    let same = fields
        .iter()
        .filter(|f| matches!(f.role, Role::Data | Role::Optional))
        .map(|f| {
            let n = &f.name;
            quote_spanned! { f.ty.span() => && self.#n == other.#n }
        });
    let data = fields.iter().filter_map(|f| {
        let (n, js) = (&f.name, &f.js);
        match f.role {
            Role::Data => Some(quote_spanned! { f.ty.span() => out.set(#js, &self.#n); }),
            Role::Optional => Some(quote_spanned! { f.ty.span() => out.opt(#js, &self.#n); }),
            Role::Event | Role::Slot { .. } | Role::Element | Role::Func { .. } | Role::Render => {
                None
            }
        }
    });
    let views = fields.iter().filter_map(|f| {
        let (n, js) = (&f.name, &f.js);
        match f.role {
            Role::Slot { optional: false } => Some(quote! { out.slot(#js, &self.#n); }),
            Role::Slot { optional: true } => Some(quote! { out.slot_opt(#js, &self.#n); }),
            Role::Element => Some(quote! { out.element(#js, &self.#n); }),
            _ => None,
        }
    });
    let events = fields.iter().filter_map(|f| {
        let (n, js) = (&f.name, &f.js);
        let span = f.ty.span();
        match f.role {
            Role::Event => Some(quote_spanned! { span => out.event(#js, &self.#n); }),
            Role::Func { is_async: false } => {
                Some(quote_spanned! { span => out.func(#js, &self.#n); })
            }
            Role::Func { is_async: true } => {
                Some(quote_spanned! { span => out.async_func(#js, &self.#n); })
            }
            Role::Render => Some(quote_spanned! { span => out.render(#js, &self.#n); }),
            _ => None,
        }
    });

    Ok(quote! {
        #(#docs)*
        #vis struct #name;

        #[doc = concat!("Props of [`", #name_str, "`].")]
        #[derive(Clone)]
        #(#others)*
        #vis struct #props_ty { #(#struct_fields),* }

        #builder

        #(const _: &[u8] = ::core::include_bytes!(#tracked);)*

        #[cfg(target_arch = "wasm32")]
        #[doc(hidden)]
        #[allow(non_snake_case)]
        mod #bindings {
            use ::doxa::ui::__private::wasm_bindgen;
            #[wasm_bindgen::prelude::wasm_bindgen(module = #spec, wasm_bindgen = ::doxa::ui::__private::wasm_bindgen)]
            extern "C" {
                pub fn load() -> wasm_bindgen::JsValue;
            }
        }

        impl ::doxa::ui::react::IslandProps for #props_ty {
            const ISLAND: ::doxa::ui::react::Island = ::doxa::ui::react::Island {
                name: #name_str,
                module: #module,
                export: #export,
                lazy: #lazy,
                #[cfg(target_arch = "wasm32")]
                load: #bindings::load,
            };

            fn same_data(&self, other: &Self) -> bool {
                true #(#same)*
            }

            fn data(&self, out: &mut ::doxa::ui::react::Data) {
                #(#data)*
            }

            #[allow(unused_variables)]
            fn views(&self, out: &mut ::doxa::ui::react::Views) {
                #(#views)*
            }

            #[allow(unused_variables)]
            fn events(&self, out: &mut ::doxa::ui::react::Events) {
                #(#events)*
            }
        }

        impl ::doxa::ui::Component for #name {
            type Props = #props_ty;
            const NAME: &'static str = #name_str;

            fn render(props: #props_ty) -> ::doxa::ui::RenderFuture {
                ::doxa::ui::react::render(props)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_camel_cased() {
        assert_eq!(camel("on_change"), "onChange");
        assert_eq!(camel("read_only_mode"), "readOnlyMode");
        assert_eq!(camel("value"), "value");
        assert_eq!(camel("_private"), "private");
    }

    #[test]
    fn local_modules_resolve_under_the_crate() {
        let lit = |s: &str| LitStr::new(s, proc_macro2::Span::call_site());
        assert_eq!(
            specifier(&lit("./ts/x.tsx")).unwrap(),
            "doxa-island:ts/x.tsx"
        );
        assert_eq!(
            specifier(&lit("@monaco-editor/react")).unwrap(),
            "@monaco-editor/react"
        );
        assert!(specifier(&lit("/abs.tsx")).is_err());
    }
}
