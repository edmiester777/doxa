//! What a shared file needs to compile in both halves: the per-role prelude,
//! `#[server]` / `#[client]`, and the derives that mean nothing to a browser.

use proc_macro2::TokenStream;
use quote::quote;
use syn::parse::Parse;
use syn::{Data, DeriveInput, Fields, Ident, Type};

use doxa_macro_support::{tag, Side};

/// `doxa::prelude!()`: the glob for this crate's role.
pub fn prelude(input: TokenStream) -> syn::Result<TokenStream> {
    if !input.is_empty() {
        return Err(syn::Error::new_spanned(
            input,
            "`prelude!()` takes no arguments",
        ));
    }
    let (half, service) = match doxa_macro_support::Role::current() {
        doxa_macro_support::Role::Client => (quote!(client), true),
        doxa_macro_support::Role::Api => (quote!(api), true),
        doxa_macro_support::Role::Server => (quote!(server), false),
    };
    let service = service.then(|| {
        quote! {
            /// The package name this crate's routes and entities carry, which names its service.
            #[allow(dead_code)]
            pub const PACKAGE: &str = ::core::env!("CARGO_PKG_NAME");

            /// This crate's service: its server's base URL, layers, cache and session.
            #[allow(dead_code)]
            pub fn service() -> ::std::rc::Rc<::doxa::client::Service> {
                ::doxa::client::service(PACKAGE)
            }
        }
    });
    Ok(quote! {
        #[allow(unused_imports)]
        use ::doxa::#half::prelude::*;
        #service
    })
}

/// `#[server]` / `#[client]` on any item: keep it only in that half.
pub fn only(side: Side, args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    if !args.is_empty() {
        return Err(syn::Error::new_spanned(
            args,
            "this attribute takes no arguments",
        ));
    }
    Ok(tag(side, item))
}

/// `#[identity(entity = "Widget", id = id, key = WidgetKey { name })]`.
struct IdentityArgs {
    entity: Option<syn::LitStr>,
    id: Option<Ident>,
    key: Option<(syn::Path, Vec<Ident>)>,
}

fn parse_identity(input: &DeriveInput) -> syn::Result<IdentityArgs> {
    let mut out = IdentityArgs {
        entity: None,
        id: None,
        key: None,
    };
    for attr in input.attrs.iter().filter(|a| a.path().is_ident("identity")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("entity") {
                out.entity = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("id") {
                out.id = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("key") {
                let value = meta.value()?;
                let path: syn::Path = value.parse()?;
                let content;
                syn::braced!(content in value);
                let fields = content
                    .parse_terminated(Ident::parse, syn::Token![,])?
                    .into_iter()
                    .collect();
                out.key = Some((path, fields));
            } else {
                return Err(
                    meta.error("unknown `identity` option; expected `entity`, `id` or `key`")
                );
            }
            Ok(())
        })?;
    }
    Ok(out)
}

/// `#[derive(Identity)]`: the id the client cache stores a value under.
pub fn derive_identity(input: TokenStream) -> syn::Result<TokenStream> {
    let input: DeriveInput = syn::parse2(input)?;
    let name = &input.ident;
    let args = parse_identity(&input)?;
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            name,
            "`Identity` derives on a struct",
        ));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new_spanned(
            name,
            "`Identity` needs named fields",
        ));
    };
    let id = args.id.unwrap_or_else(|| Ident::new("id", name.span()));
    let id_ty: &Type = fields
        .named
        .iter()
        .find(|f| f.ident.as_ref() == Some(&id))
        .map(|f| &f.ty)
        .ok_or_else(|| {
            syn::Error::new_spanned(
                &id,
                format!("`{name}` has no field `{id}`; name its immutable id with `#[identity(id = …)]`"),
            )
        })?;
    let entity = args
        .entity
        .unwrap_or_else(|| syn::LitStr::new(&name.to_string(), name.span()));

    let id_field = id.to_string();
    let key_consts = args.key.as_ref().map(|(path, fields)| {
        let ty = path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        let fields = fields.iter().map(|f| f.to_string());
        quote! {
            const KEY_TYPE: ::core::option::Option<&'static str> = ::core::option::Option::Some(#ty);
            const KEY_FIELDS: &'static [&'static str] = &[#(#fields),*];
        }
    });
    let route_key = args.key.as_ref().map(|(path, _)| {
        quote! {
            fn route_key(&self) -> ::core::option::Option<::doxa::wire::__Value> {
                ::doxa::wire::key_value(&<#path as ::core::convert::From<&Self>>::from(self))
            }
        }
    });
    let key = args.key.map(|(path, fields)| {
        quote! {
            impl ::core::convert::From<&#name> for #path {
                fn from(value: &#name) -> Self {
                    #path { #(#fields: ::core::clone::Clone::clone(&value.#fields)),* }
                }
            }

            impl ::doxa::wire::KeyedBy<#path> for #name {}
        }
    });

    // A cached entity passes where an owned one is taken, e.g. a prop.
    let owned = tag(
        Side::Client,
        quote! {
            impl ::core::convert::From<::doxa::client::Cached<#name>> for #name {
                fn from(value: ::doxa::client::Cached<#name>) -> Self {
                    ::doxa::client::Cached::into_inner(value)
                }
            }
        },
    );

    Ok(quote! {
        impl ::doxa::wire::Identity for #name {
            type Id = #id_ty;
            const ENTITY_TYPE: &'static str = #entity;
            const PACKAGE: &'static str = ::core::env!("CARGO_PKG_NAME");
            const ID_FIELD: &'static str = #id_field;
            #key_consts
            fn identity(&self) -> #id_ty {
                ::core::clone::Clone::clone(&self.#id)
            }
            #route_key
        }

        #key
        #owned
    })
}

/// `client_pub! { mod api; }`: these items are `pub` in the client half and as written on the server.
pub fn client_pub(input: TokenStream) -> syn::Result<TokenStream> {
    let mut file: syn::File = syn::parse2(input)?;
    if doxa_macro_support::is_client() {
        for item in &mut file.items {
            *visibility(item)? = syn::parse_quote!(pub);
        }
    }
    let items = &file.items;
    Ok(quote!(#(#items)*))
}

fn visibility(item: &mut syn::Item) -> syn::Result<&mut syn::Visibility> {
    use syn::Item;
    Ok(match item {
        Item::Mod(i) => &mut i.vis,
        Item::Use(i) => &mut i.vis,
        Item::Fn(i) => &mut i.vis,
        Item::Struct(i) => &mut i.vis,
        Item::Enum(i) => &mut i.vis,
        Item::Type(i) => &mut i.vis,
        Item::Const(i) => &mut i.vis,
        Item::Static(i) => &mut i.vis,
        Item::Trait(i) => &mut i.vis,
        other => {
            return Err(syn::Error::new_spanned(
                other,
                "`client_pub!` takes items with a visibility, such as `mod x;` or `use …;`",
            ))
        }
    })
}
