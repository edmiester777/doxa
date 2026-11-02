//! `#[page("/path/{param}", load = …)]`: a component reachable at a path.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{Expr, LitStr, Token};

use crate::component::{self, Options, Parsed};

pub(crate) struct Args {
    path: LitStr,
    load: Option<Expr>,
    lazy: bool,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let path: LitStr = input.parse()?;
        let (mut load, mut lazy) = (None, false);
        while input.parse::<Option<Token![,]>>()?.is_some() && !input.is_empty() {
            let key: syn::Ident = input.parse()?;
            match key.to_string().as_str() {
                "lazy" => lazy = true,
                "load" => {
                    input.parse::<Token![=]>()?;
                    load = Some(input.parse()?)
                }
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!("unknown option `{other}`; expected `load` or `lazy`"),
                    ))
                }
            }
        }
        Ok(Args { path, load, lazy })
    }
}

fn template_names(path: &str) -> Vec<String> {
    path.split('/')
        .filter_map(|s| s.strip_prefix('{')?.strip_suffix('}'))
        .map(|s| s.trim_start_matches('*').to_owned())
        .collect()
}

pub(crate) fn expand(args: Args, parsed: &Parsed) -> syn::Result<TokenStream> {
    let name = &parsed.item.sig.ident;
    let vis = &parsed.item.vis;
    let props_ty = format_ident!("{}Props", name);
    let path = &args.path;
    let in_path = template_names(&path.value());

    for t in &in_path {
        if !parsed.props.iter().any(|p| p.name == t) {
            return Err(syn::Error::new(
                path.span(),
                format!("`{{{t}}}` has no matching parameter on `{name}`"),
            ));
        }
    }
    let mut fields = Vec::new();
    let mut route_params = Vec::new();
    let mut fill = Vec::new();
    for p in &parsed.props {
        let (n, s) = (&p.name, p.name.to_string());
        if in_path.contains(&s) {
            fields.push(quote! { #n: segments.get(#s)?.parse().ok()? });
            route_params.push(quote! { #n: impl ::std::string::ToString });
            fill.push(quote! { (#s, &#n.to_string()) });
        } else if p.optional {
            fields.push(quote! { #n: match segments.query(#s) {
                ::core::option::Option::Some(v) => ::core::option::Option::Some(v.parse().ok()?),
                ::core::option::Option::None => ::core::option::Option::None,
            } });
        } else if let Some(default) = &p.default {
            fields.push(quote! { #n: match segments.query(#s) {
                ::core::option::Option::Some(v) => v.parse().ok()?,
                ::core::option::Option::None => #default,
            } });
        } else {
            return Err(syn::Error::new(
                n.span(),
                format!("`{s}` isn't in the path `{}`; make it an `Option` or `#[prop(default)]` to read it from the query", path.value()),
            ));
        }
    }
    let load = args.load.as_ref().map(|l| {
        quote! {
            fn load(p: &#props_ty) -> ::core::option::Option<::doxa::ui::Prefetch> {
                let load: fn(&#props_ty) -> _ = #l;
                ::core::option::Option::Some(::doxa::ui::Prefetch::of(load(p)))
            }
        }
    });
    let opts = Options {
        lazy: args.lazy,
        ..Options::default()
    };
    let component = component::expand(opts, parsed);
    let chunk = args.lazy.then(|| {
        let loader = component::lazy_mod(name);
        quote! {
            #[cfg(target_arch = "wasm32")]
            fn chunk() -> ::core::option::Option<::doxa::ui::Prefetch> {
                ::core::option::Option::Some(::doxa::ui::Prefetch::of(#loader::LOADER.load()))
            }
        }
    });
    Ok(quote! {
        #component

        impl ::doxa::ui::Page for #name {
            const PATH: &'static str = #path;
            fn parse(segments: &::doxa::ui::Segments) -> ::core::option::Option<#props_ty> {
                ::core::option::Option::Some(#props_ty { #(#fields),* })
            }
            #load
            #chunk
        }

        impl #name {
            /// The URL of this page.
            #vis fn route(#(#route_params),*) -> ::doxa::ui::Route {
                ::doxa::ui::Route::fill(#path, &[#(#fill),*])
            }
        }
    })
}
