//! `#[npm(module = "…")] extern "js" { … }`: a plain JS module as typed Rust.
//!
//! Strings, numbers, bools and the block's own JS types pass through as they are; every
//! other argument and return value crosses as JSON-compatible data through serde.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::parse::Parser;
use syn::{
    FnArg, ForeignItem, ForeignItemFn, Ident, ItemForeignMod, LitStr, Pat, ReturnType, Type,
};

pub(crate) struct Args {
    module: LitStr,
    export: Option<LitStr>,
    lazy: bool,
}

impl Args {
    pub(crate) fn parse(tokens: TokenStream) -> syn::Result<Args> {
        let (mut module, mut export, mut lazy) = (None, None, false);
        let parser = syn::meta::parser(|meta| {
            if meta.path.is_ident("module") {
                module = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("export") {
                export = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("lazy") {
                lazy = true;
            } else {
                return Err(meta.error("expected `module`, `export` or `lazy`"));
            }
            Ok(())
        });
        parser.parse2(tokens)?;
        let module = module.ok_or_else(|| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                "`#[npm]` needs `module = \"…\"`, e.g. `#[npm(module = \"cronstrue\")]`",
            )
        })?;
        Ok(Args {
            module,
            export,
            lazy,
        })
    }
}

/// How a value crosses into or out of JS.
enum Crossing {
    /// As wasm-bindgen passes it.
    Direct,
    /// Through `serde_wasm_bindgen`.
    Serde,
}

const DIRECT: &[&str] = &[
    "str", "String", "bool", "f64", "f32", "i8", "i16", "i32", "u8", "u16", "u32", "JsValue",
];

fn crossing(ty: &Type, js_types: &[Ident]) -> Crossing {
    let ty = match ty {
        Type::Reference(r) => &*r.elem,
        t => t,
    };
    let Type::Path(p) = ty else {
        return Crossing::Serde;
    };
    let Some(last) = p.path.segments.last() else {
        return Crossing::Serde;
    };
    let direct = DIRECT.iter().any(|d| last.ident == d)
        || js_types.contains(&last.ident)
        || p.path
            .segments
            .first()
            .is_some_and(|s| s.ident == "js_sys" || s.ident == "web_sys");
    if direct {
        Crossing::Direct
    } else {
        Crossing::Serde
    }
}

/// `T` in `Result<T, JsError>`, and whether it was one.
fn ok_type(ret: &ReturnType) -> (Option<Type>, bool) {
    let ReturnType::Type(_, ty) = ret else {
        return (None, false);
    };
    if let Type::Path(p) = &**ty {
        if let Some(seg) = p.path.segments.last().filter(|s| s.ident == "Result") {
            if let syn::PathArguments::AngleBracketed(a) = &seg.arguments {
                if let Some(syn::GenericArgument::Type(t)) = a.args.first() {
                    let unit = matches!(t, Type::Tuple(tt) if tt.elems.is_empty());
                    return ((!unit).then(|| t.clone()), true);
                }
            }
        }
    }
    let unit = matches!(&**ty, Type::Tuple(tt) if tt.elems.is_empty());
    ((!unit).then(|| (**ty).clone()), false)
}

/// The JS name: `#[npm(export = "…")]` on the function, else its own name in camelCase.
fn js_name(f: &ForeignItemFn) -> syn::Result<String> {
    let mut name = None;
    for attr in f.attrs.iter().filter(|a| a.path().is_ident("npm")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("export") {
                name = Some(meta.value()?.parse::<LitStr>()?.value());
                Ok(())
            } else {
                Err(meta.error("expected `export = \"…\"`"))
            }
        })?;
    }
    Ok(name.unwrap_or_else(|| camel(&f.sig.ident.to_string())))
}

fn camel(name: &str) -> String {
    let mut out = String::new();
    let mut up = false;
    for c in name.chars() {
        if c == '_' {
            up = true;
        } else if up {
            out.extend(c.to_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) fn expand(args: Args, block: ItemForeignMod) -> syn::Result<TokenStream> {
    let module = crate::react::specifier(&args.module)?;
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

    let js_types: Vec<Ident> = block
        .items
        .iter()
        .filter_map(|i| match i {
            ForeignItem::Type(t) => Some(t.ident.clone()),
            _ => None,
        })
        .collect();
    let mut fns = Vec::new();
    for item in &block.items {
        match item {
            ForeignItem::Fn(f) => fns.push(f.clone()),
            ForeignItem::Type(_) => {}
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    "`#[npm]` blocks hold `fn`s and `type`s",
                ))
            }
        }
    }
    if args.lazy {
        if let Some(t) = js_types.first() {
            return Err(syn::Error::new_spanned(
                t,
                "a `lazy` module is loaded on first call, so its block holds only `async fn`s",
            ));
        }
        if let Some(f) = fns.iter().find(|f| f.sig.asyncness.is_none()) {
            return Err(syn::Error::new_spanned(
                &f.sig.ident,
                "a `lazy` module is loaded on first call, so this must be an `async fn`",
            ));
        }
    }

    let names: Vec<String> = fns.iter().map(js_name).collect::<syn::Result<_>>()?;
    let spec = if args.lazy {
        format!("doxa-npm:lazy:{}:{module}", names.join(","))
    } else {
        module.clone()
    };
    let bindings = format_ident!(
        "__doxa_npm_{}",
        spec.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
    );

    let mut raw = Vec::new();
    let mut wrappers = Vec::new();
    for (f, name) in fns.iter().zip(&names) {
        let (r, w) = function(f, name, &js_types, &bindings)?;
        raw.push(r);
        wrappers.push(w);
    }

    let types_wasm = js_types.iter().map(|t| {
        let default = args
            .export
            .as_ref()
            .filter(|e| e.value() == "default" && Some(t) == js_types.first())
            .map(|_| {
                let getter = format_ident!("__default_{}", t);
                quote! {
                    #[wasm_bindgen(js_name = default, thread_local_v2)]
                    static #getter: #t;
                }
            });
        quote! {
            #[derive(Clone)]
            pub type #t;
            #default
        }
    });
    let defaults = js_types.first().filter(|_| args.export.is_some()).map(|t| {
        let getter = format_ident!("__default_{}", t);
        quote! {
            impl #t {
                /// The module's default export.
                pub fn get() -> #t {
                    #[cfg(target_arch = "wasm32")]
                    {
                        #bindings::#getter.with(::core::clone::Clone::clone)
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        ::core::unreachable!("npm modules load only in the browser")
                    }
                }
            }
        }
    });
    let natives = js_types.iter().map(|t| {
        quote! {
            #[cfg(not(target_arch = "wasm32"))]
            #[derive(Clone)]
            #[doc = "A JS value; only the browser has one."]
            pub struct #t(());
        }
    });
    let reexports = js_types
        .iter()
        .map(|t| quote!(#[cfg(target_arch = "wasm32")] pub use #bindings::#t;));

    Ok(quote! {
        #(const _: &[u8] = ::core::include_bytes!(#tracked);)*

        #[cfg(target_arch = "wasm32")]
        #[doc(hidden)]
        #[allow(non_snake_case, non_upper_case_globals)]
        mod #bindings {
            #[allow(unused_imports)]
            use super::*;
            use ::doxa::ui::__private::wasm_bindgen;
            use wasm_bindgen::prelude::wasm_bindgen;
            #[wasm_bindgen(module = #spec, wasm_bindgen = ::doxa::ui::__private::wasm_bindgen)]
            extern "C" {
                #(#types_wasm)*
                #(#raw)*
            }
        }

        #(#reexports)*
        #(#natives)*
        #defaults
        #(#wrappers)*
    })
}

/// The raw extern for `f`, and the typed wrapper around it.
fn function(
    f: &ForeignItemFn,
    js: &str,
    js_types: &[Ident],
    bindings: &Ident,
) -> syn::Result<(TokenStream, TokenStream)> {
    let name = &f.sig.ident;
    let raw_name = format_ident!("__{}", name);
    let docs = f.attrs.iter().filter(|a| a.path().is_ident("doc"));
    let vis = &f.vis;
    let is_async = f.sig.asyncness.is_some();
    let (ok, fallible) = ok_type(&f.sig.output);

    let mut raw_params = Vec::new();
    let mut params = Vec::new();
    let mut pass = Vec::new();
    let mut method = false;
    for (i, arg) in f.sig.inputs.iter().enumerate() {
        let FnArg::Typed(pt) = arg else {
            return Err(syn::Error::new_spanned(
                arg,
                "write `this: &Type` for a method",
            ));
        };
        let ident = match &*pt.pat {
            Pat::Ident(p) => p.ident.clone(),
            _ => format_ident!("arg{i}"),
        };
        let ty = &pt.ty;
        if ident == "this" {
            if i != 0 {
                return Err(syn::Error::new_spanned(&pt.pat, "`this` comes first"));
            }
            method = true;
            raw_params.push(quote!(this: #ty));
            params.push(quote!(this: #ty));
            pass.push(quote!(this));
            continue;
        }
        params.push(quote!(#ident: #ty));
        match crossing(ty, js_types) {
            Crossing::Direct => {
                raw_params.push(quote!(#ident: #ty));
                pass.push(quote!(#ident));
            }
            Crossing::Serde => {
                raw_params.push(quote!(#ident: wasm_bindgen::JsValue));
                pass.push(quote! {
                    match ::doxa::ui::__private::to_js(&#ident) {
                        ::core::result::Result::Ok(v) => v,
                        ::core::result::Result::Err(e) => return __fail(e),
                    }
                });
            }
        }
    }

    // The raw call answers a JsValue (or a Promise of one); the wrapper reads it as `ok`.
    let catch = (fallible || is_async).then(|| quote!(catch,));
    let method_attr = method.then(|| quote!(method,));
    let raw_ret = if is_async || fallible || ok.is_some() {
        if catch.is_some() {
            quote!(-> ::core::result::Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>)
        } else {
            quote!(-> wasm_bindgen::JsValue)
        }
    } else {
        quote!()
    };
    let raw = quote! {
        #[wasm_bindgen(#method_attr #catch js_name = #js)]
        pub fn #raw_name(#(#raw_params),*) #raw_ret;
    };

    let js_value = |t: &Type| match t {
        Type::Path(p) => {
            p.path
                .segments
                .last()
                .is_some_and(|s| s.ident == "JsValue" || js_types.contains(&s.ident))
                || p.path
                    .segments
                    .first()
                    .is_some_and(|s| s.ident == "js_sys" || s.ident == "web_sys")
        }
        _ => false,
    };
    let read = match &ok {
        None => quote!(::core::result::Result::Ok(())),
        Some(t) => match js_value(t) {
            true => quote! {
                wasm_bindgen::JsCast::dyn_into::<#t>(value)
                    .map_err(|_| ::doxa::ui::__private::js_error("the JS value isn't the type declared"))
            },
            false => quote!(::doxa::ui::__private::from_js::<#t>(value)),
        },
    };
    let ret = &f.sig.output;
    let asyncness = &f.sig.asyncness;
    // `Ok` is the declared return type's own shape: `Result<T, JsError>` or bare `T`.
    let finish = if fallible {
        quote!(result)
    } else {
        quote!(result
            .unwrap_or_else(|e| ::core::panic!("{}: {}", #js, ::doxa::ui::__private::describe(e))))
    };
    let fail = if fallible {
        quote! {
            let __fail = |e: ::doxa::ui::JsError| -> _ { ::core::result::Result::Err(e) };
        }
    } else {
        quote! {
            let __fail = |e: ::doxa::ui::JsError| -> _ {
                ::core::panic!("{}: {}", #js, ::doxa::ui::__private::describe(e))
            };
        }
    };
    let call = if is_async {
        quote! {
            let promise = match #bindings::#raw_name(#(#pass),*) {
                ::core::result::Result::Ok(p) => p,
                ::core::result::Result::Err(e) => return __fail(::doxa::ui::__private::js_error_from(e)),
            };
            let value = match ::doxa::ui::__private::await_promise(promise).await {
                ::core::result::Result::Ok(v) => v,
                ::core::result::Result::Err(e) => return __fail(::doxa::ui::__private::js_error_from(e)),
            };
        }
    } else if catch.is_some() {
        quote! {
            let value = match #bindings::#raw_name(#(#pass),*) {
                ::core::result::Result::Ok(v) => v,
                ::core::result::Result::Err(e) => return __fail(::doxa::ui::__private::js_error_from(e)),
            };
        }
    } else if ok.is_some() {
        quote!(let value = #bindings::#raw_name(#(#pass),*);)
    } else {
        quote!(#bindings::#raw_name(#(#pass),*); let value = ();)
    };
    let wrapper = quote! {
        #(#docs)*
        #[allow(unused_variables, clippy::let_unit_value)]
        #vis #asyncness fn #name(#(#params),*) #ret {
            #[cfg(target_arch = "wasm32")]
            {
                use ::doxa::ui::__private::wasm_bindgen;
                #fail
                #call
                let _ = &value;
                let result: ::core::result::Result<_, ::doxa::ui::JsError> = #read;
                #finish
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                ::core::unreachable!("npm modules load only in the browser")
            }
        }
    };
    Ok((raw, wrapper))
}
