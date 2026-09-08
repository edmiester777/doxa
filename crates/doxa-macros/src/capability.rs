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

/// The id half of a check, as written.
///
/// A coarse gate has no object to name, so the id is a constant or the
/// tenant — and the tenant is spelled as a bare `tenant` rather than as
/// the string `"tenant"`, because it is not an id at all. It is a
/// instruction to substitute one, and doxa carries it out before the
/// consumer's UID builder is reached.
#[derive(Clone)]
pub(crate) enum EntityId {
    Literal(LitStr),
    Tenant,
}

impl EntityId {
    /// A literal id, for a default the derive works out rather than reads.
    pub fn literal(value: &str, span: proc_macro2::Span) -> Self {
        EntityId::Literal(LitStr::new(value, span))
    }

    pub fn tokens(&self) -> TokenStream {
        match self {
            EntityId::Literal(id) => quote!(::doxa::policy::ResourceId::Literal(#id)),
            EntityId::Tenant => quote!(::doxa::policy::ResourceId::Tenant),
        }
    }
}

/// `entity_id = "collection"` or `entity_id = tenant`.
pub(crate) fn parse_entity_id(input: ParseStream) -> syn::Result<EntityId> {
    if input.peek(LitStr) {
        return Ok(EntityId::Literal(input.parse()?));
    }

    let ident: Ident = input.parse().map_err(|_| {
        input.error("expected a string literal, or the bare word `tenant` for the request's tenant")
    })?;

    if ident == "tenant" {
        Ok(EntityId::Tenant)
    } else {
        Err(syn::Error::new(
            ident.span(),
            format!(
                "unknown `entity_id` form `{ident}`; expected a string literal such as \
                 \"collection\", or the bare word `tenant`",
            ),
        ))
    }
}

/// One `(action, entity_type, entity_id)` triple. Shared with the
/// `Actions` derive, which builds them from defaults rather than
/// parsing them.
pub(crate) struct CheckArgs {
    pub action: LitStr,
    pub entity_type: LitStr,
    pub entity_id: EntityId,
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
                entity_id = Some(parse_entity_id(&content)?);
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

    let declaration = declare(&input.ident, &args.name, &args.description, &args.checks);

    quote! {
        #input
        #declaration
    }
}

/// The capability half of a declaration: the const, the [`Capable`] impl
/// binding it to `marker`, and the catalog registration.
///
/// Shared by `#[capability]` and `#[derive(Actions)]` so a capability
/// means the same thing however it was declared — in particular so that
/// both land in the catalog, which is the whole point of registering at
/// the declaration rather than in a list somewhere else.
pub(crate) fn declare(
    marker: &Ident,
    name: &LitStr,
    description: &LitStr,
    checks: &[CheckArgs],
) -> TokenStream {
    let const_name = Ident::new(&format!("_DOXA_CAPABILITY_{marker}"), marker.span());

    let check_tokens: Vec<_> = checks
        .iter()
        .map(|c| {
            let action = &c.action;
            let entity_type = &c.entity_type;
            let entity_id = c.entity_id.tokens();
            quote! {
                ::doxa::policy::CapabilityCheck {
                    action: #action,
                    entity_type: #entity_type,
                    entity_id: #entity_id,
                }
            }
        })
        .collect();

    quote! {
        // The const is named after the marker, which is `CamelCase` by
        // convention and would otherwise trip `non_upper_case_globals`
        // in every crate that declares a capability.
        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        const #const_name: ::doxa::policy::Capability = ::doxa::policy::Capability {
            name: #name,
            description: #description,
            checks: &[#(#check_tokens),*],
        };

        impl ::doxa::policy::Capable for #marker {
            const CAPABILITY: &'static ::doxa::policy::Capability = &#const_name;
        }

        // Declaring a capability is what puts it in the catalog, so
        // `doxa::policy::capabilities()` can answer without anyone
        // maintaining a list. Expands to nothing without the `catalog`
        // feature.
        ::doxa::policy::inventory::submit! { &#const_name }
    }
}
