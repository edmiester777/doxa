//! `#[derive(State)]`, `#[service]`, `#[layers]`, and the mount each handler submits.

use proc_macro2::TokenStream;
use quote::quote;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::{DeriveInput, ItemFn, ItemStruct, Path, Result, Token, Type};

/// This crate's `Key`, the same wherever it's spelled.
fn crate_key() -> TokenStream {
    quote!({ ::doxa::__private::crate_key(::core::option_env!("CARGO_CRATE_NAME")) })
}

/// `#[derive(State)]`: the state this crate's handlers are mounted under.
pub fn derive_state(input: DeriveInput) -> Result<TokenStream> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "a server's state is one concrete type, so it can't be generic",
        ));
    }
    let name = &input.ident;
    let key = crate_key();
    Ok(quote! {
        impl ::doxa::__private::Resolve<#name> for ::doxa::__private::Key<#key> {}
    })
}

/// The span a route runs under: its handler, method and template, the caller's tenant, and a
/// field per path parameter.
pub struct RouteSpan<'a> {
    /// `false` for `trace = false`.
    pub on: bool,
    pub handler: &'a str,
    pub route: &'a str,
    pub path: &'a str,
    /// `[package.metadata.doxa] tenant_field`, else `tenant`.
    pub tenant_field: &'a str,
}

impl RouteSpan<'_> {
    fn maker(&self) -> TokenStream {
        if !self.on {
            return quote!(::core::option::Option::None);
        }
        let (handler, route) = (self.handler, self.route);
        let tenant = syn::LitStr::new(self.tenant_field, proc_macro2::Span::call_site());
        let fixed = ["handler", "route", self.tenant_field];
        let params = path_params(self.path)
            .into_iter()
            .filter(|p| !fixed.contains(&p.as_str()))
            .map(|p| syn::LitStr::new(&p, proc_macro2::Span::call_site()));
        let t = quote!(::doxa::__private::tracing);
        quote! {
            ::core::option::Option::Some((|tenant: ::core::option::Option<&str>| #t::info_span!(
                "route",
                handler = #handler,
                route = #route,
                #tenant = tenant,
                #(#params = #t::field::Empty,)*
            )) as fn(::core::option::Option<&str>) -> #t::Span)
        }
    }
}

/// The crate's `tenant_field`, which `doxa_role` passes down from `build.rs`.
pub fn tenant_field() -> String {
    std::env::var("DOXA_TENANT_FIELD").unwrap_or_else(|_| "tenant".to_owned())
}

/// Every `{name}` and `{*name}` in a template.
fn path_params(path: &str) -> Vec<String> {
    path.split('{')
        .skip(1)
        .filter_map(|s| s.split_once('}'))
        .map(|(name, _)| name.trim_start_matches('*').to_owned())
        .filter(|name| !name.is_empty())
        .collect()
}

/// The `Mount` a handler submits, unless it said `mount = false`.
pub fn mount(item_fn: &ItemFn, span: &RouteSpan<'_>) -> TokenStream {
    let name = &item_fn.sig.ident;
    let handler = name.to_string();
    let key = crate_key();
    let span = span.maker();
    quote! {
        ::doxa::__private::inventory::submit! {
            ::doxa::__private::Mount {
                module: ::core::module_path!(),
                handler: #handler,
                build: |state| ::doxa::__private::mount::<_, #key>(::doxa::routes!(#name), state, #span),
                doc: || ::doxa::__private::describe::<_, #key>(::doxa::routes!(#name)),
            }
        }
    }
}

/// `#[service]` / `#[service(layers = stack)]` on a unit struct.
pub fn service(args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let item: ItemStruct = syn::parse2(item)?;
    if doxa_macro_support::is_client() {
        return Err(syn::Error::new_spanned(
            &item.ident,
            "a service groups a server's handlers, and this crate is a client half",
        ));
    }
    let mut layers: Option<Path> = None;
    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("layers") {
            layers = Some(meta.value()?.parse()?);
            Ok(())
        } else {
            Err(meta.error("`#[service]` takes `layers = stack`"))
        }
    });
    parser.parse2(args)?;
    let name = item.ident.to_string();
    let layers = match layers {
        Some(stack) => quote!(::core::option::Option::Some(
            ::doxa::__private::stacked::<#stack>()
        )),
        None => quote!(::core::option::Option::None),
    };
    Ok(doxa_macro_support::tag(
        doxa_macro_support::Side::Server,
        quote! {
            // Only doxa reads it.
            #[allow(dead_code)]
            #item

            ::doxa::__private::inventory::submit! {
                ::doxa::__private::Service {
                    name: #name,
                    module: ::core::module_path!(),
                    layers: #layers,
                }
            }
        },
    ))
}

/// `#[layers(docs = [...])]` on `fn(Routes, &State) -> Routes`.
pub fn layers(args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let item_fn: ItemFn = syn::parse2(item)?;
    let mut docs: Vec<Type> = Vec::new();
    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("docs") {
            let value = meta.value()?;
            let content;
            syn::bracketed!(content in value);
            let list = Punctuated::<Type, Token![,]>::parse_terminated(&content)?;
            docs.extend(list);
            Ok(())
        } else {
            Err(meta.error("`#[layers]` takes `docs = [...]`"))
        }
    });
    parser.parse2(args)?;
    let sig = &item_fn.sig;
    if !sig.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &sig.generics,
            "a layer stack reads the server's one state, so it can't be generic",
        ));
    }
    let state = match (sig.inputs.len(), sig.inputs.iter().nth(1)) {
        (2, Some(syn::FnArg::Typed(pt))) => match &*pt.ty {
            Type::Reference(r) if r.mutability.is_none() => (*r.elem).clone(),
            _ => return Err(shape(sig)),
        },
        _ => return Err(shape(sig)),
    };
    let name = &sig.ident;
    let vis = &item_fn.vis;
    Ok(quote! {
        #item_fn

        #[doc(hidden)]
        #[allow(non_camel_case_types)]
        #vis enum #name {}

        impl ::doxa::__private::StackDocs for #name {
            fn docs() -> ::doxa::LayerContribution {
                #[allow(unused_mut)]
                let mut docs = ::doxa::LayerContribution::new();
                #(docs.merge(<#docs as ::doxa::__private::StackDocs>::docs());)*
                docs
            }
        }

        impl ::doxa::__private::Layers for #name {
            type State = #state;

            fn apply(routes: ::doxa::Routes, state: &#state) -> ::doxa::Routes {
                #name(routes, state)
            }
        }
    })
}

fn shape(sig: &syn::Signature) -> syn::Error {
    syn::Error::new_spanned(
        sig,
        "a layer stack is `fn(routes: doxa::Routes, state: &State) -> doxa::Routes`",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span_for(path: &str, tenant_field: &str) -> String {
        RouteSpan {
            on: true,
            handler: "get_widget",
            route: "GET /widgets",
            path,
            tenant_field,
        }
        .maker()
        .to_string()
        .replace(' ', "")
    }

    #[test]
    fn the_tenant_lands_on_the_configured_field() {
        let out = span_for("/widgets/{id}", "company_id");
        assert!(out.contains("\"company_id\"=tenant"), "{out}");
        assert!(!out.contains("\"tenant\"="), "{out}");
    }

    #[test]
    fn a_path_parameter_named_like_the_tenant_field_is_not_declared_twice() {
        let out = span_for("/orgs/{company_id}", "company_id");
        assert_eq!(out.matches("\"company_id\"").count(), 1, "{out}");
    }
}
