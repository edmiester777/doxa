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
        let e = export.value();
        let ident_like = e
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_' || c == '$')
            && e.chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '$');
        if !ident_like {
            return Err(syn::Error::new(
                export.span(),
                "`export` is a JS name, or `default`",
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
        let (mut optional, mut event, mut rename) = (false, false, None);
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
                } else if m.path.is_ident("rename") {
                    rename = Some(m.value()?.parse::<LitStr>()?.value());
                } else {
                    return Err(m.error("expected `optional`, `event` or `rename = \"…\"`"));
                }
                Ok(())
            })?;
        }
        f.attrs = kept;
        let role = match (optional, event) {
            (true, true) => {
                return Err(syn::Error::new(
                    name.span(),
                    "a prop is `optional` or an `event`, not both",
                ))
            }
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
                || matches!(f.role, Role::Optional)
                || (matches!(f.role, Role::Data) && last_segment_is(&f.ty, "Option")))
            .then(|| quote!(::core::default::Default::default())),
            optional: false,
        })
        .collect();
    let builder = builder(vis, name, &props_ty, &props);

    let same = fields
        .iter()
        .filter(|f| !matches!(f.role, Role::Event))
        .map(|f| {
            let n = &f.name;
            quote_spanned! { f.ty.span() => && self.#n == other.#n }
        });
    let data = fields.iter().filter_map(|f| {
        let (n, js) = (&f.name, &f.js);
        match f.role {
            Role::Data => Some(quote_spanned! { f.ty.span() => out.set(#js, &self.#n); }),
            Role::Optional => Some(quote_spanned! { f.ty.span() => out.opt(#js, &self.#n); }),
            Role::Event => None,
        }
    });
    let events = fields.iter().filter_map(|f| {
        let (n, js) = (&f.name, &f.js);
        matches!(f.role, Role::Event)
            .then(|| quote_spanned! { f.ty.span() => out.event(#js, &self.#n); })
    });

    Ok(quote! {
        #(#docs)*
        #vis struct #name;

        #[doc = concat!("Props of [`", #name_str, "`].")]
        #[derive(Clone)]
        #(#others)*
        #vis struct #props_ty { #(#struct_fields),* }

        #builder

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
