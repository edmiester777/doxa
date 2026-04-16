//! `#[capability]` attribute macro.

use proc_macro2::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{Ident, LitStr, Token};

struct CapabilityArgs {
    name: LitStr,
    description: LitStr,
    checks: Vec<CheckArgs>,
}

struct CheckArgs {
    action: LitStr,
    entity_type: LitStr,
    entity_id: LitStr,
}

mod kw {
    syn::custom_keyword!(name);
    syn::custom_keyword!(description);
    syn::custom_keyword!(checks);
    syn::custom_keyword!(action);
    syn::custom_keyword!(entity_type);
    syn::custom_keyword!(entity_id);
}

impl Parse for CheckArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let content;
        syn::parenthesized!(content in input);

        let mut action = None;
        let mut entity_type = None;
        let mut entity_id = None;

        while !content.is_empty() {
            let lookahead = content.lookahead1();
            if lookahead.peek(kw::action) {
                content.parse::<kw::action>()?;
                content.parse::<Token![=]>()?;
                action = Some(content.parse::<LitStr>()?);
            } else if lookahead.peek(kw::entity_type) {
                content.parse::<kw::entity_type>()?;
                content.parse::<Token![=]>()?;
                entity_type = Some(content.parse::<LitStr>()?);
            } else if lookahead.peek(kw::entity_id) {
                content.parse::<kw::entity_id>()?;
                content.parse::<Token![=]>()?;
                entity_id = Some(content.parse::<LitStr>()?);
            } else {
                return Err(lookahead.error());
            }
            let _ = content.parse::<Token![,]>();
        }

        Ok(CheckArgs {
            action: action.ok_or_else(|| content.error("missing `action = \"...\"`"))?,
            entity_type: entity_type
                .ok_or_else(|| content.error("missing `entity_type = \"...\"`"))?,
            entity_id: entity_id.ok_or_else(|| content.error("missing `entity_id = \"...\"`"))?,
        })
    }
}

impl Parse for CapabilityArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut name = None;
        let mut description = None;
        let mut checks = Vec::new();

        while !input.is_empty() {
            let lookahead = input.lookahead1();
            if lookahead.peek(kw::name) {
                input.parse::<kw::name>()?;
                input.parse::<Token![=]>()?;
                name = Some(input.parse::<LitStr>()?);
            } else if lookahead.peek(kw::description) {
                input.parse::<kw::description>()?;
                input.parse::<Token![=]>()?;
                description = Some(input.parse::<LitStr>()?);
            } else if lookahead.peek(kw::checks) {
                input.parse::<kw::checks>()?;
                checks.push(input.parse::<CheckArgs>()?);
            } else {
                return Err(lookahead.error());
            }
            let _ = input.parse::<Token![,]>();
        }

        if checks.is_empty() {
            return Err(input.error("at least one `checks(...)` block is required"));
        }

        Ok(CapabilityArgs {
            name: name.ok_or_else(|| input.error("missing `name = \"...\"`"))?,
            description: description
                .ok_or_else(|| input.error("missing `description = \"...\"`"))?,
            checks,
        })
    }
}

pub fn expand(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = match syn::parse2::<CapabilityArgs>(attr) {
        Ok(a) => a,
        Err(e) => return e.to_compile_error(),
    };
    let input = match syn::parse2::<syn::ItemStruct>(item.clone()) {
        Ok(s) => s,
        Err(_) => {
            return syn::Error::new_spanned(item, "#[capability] can only be applied to a struct")
                .to_compile_error();
        }
    };

    let struct_name = &input.ident;
    let const_name = Ident::new(
        &format!("_DOXA_CAPABILITY_{struct_name}"),
        struct_name.span(),
    );
    let cap_name = &args.name;
    let cap_description = &args.description;

    let check_tokens: Vec<_> = args
        .checks
        .iter()
        .map(|c| {
            let action = &c.action;
            let entity_type = &c.entity_type;
            let entity_id = &c.entity_id;
            quote! {
                ::doxa_policy::CapabilityCheck {
                    action: #action,
                    entity_type: #entity_type,
                    entity_id: #entity_id,
                }
            }
        })
        .collect();

    quote! {
        #input

        #[doc(hidden)]
        const #const_name: ::doxa_policy::Capability = ::doxa_policy::Capability {
            name: #cap_name,
            description: #cap_description,
            checks: &[#(#check_tokens),*],
        };

        impl ::doxa_policy::Capable for #struct_name {
            const CAPABILITY: &'static ::doxa_policy::Capability = &#const_name;
        }
    }
}
