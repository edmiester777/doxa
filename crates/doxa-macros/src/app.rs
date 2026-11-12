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

/// The `Mount` a handler submits, unless it said `mount = false`.
pub fn mount(item_fn: &ItemFn) -> TokenStream {
    let name = &item_fn.sig.ident;
    let handler = name.to_string();
    let key = crate_key();
    quote! {
        ::doxa::__private::inventory::submit! {
            ::doxa::__private::Mount {
                module: ::core::module_path!(),
                handler: #handler,
                build: |state| ::doxa::__private::mount::<_, #key>(::doxa::routes!(#name), state),
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
