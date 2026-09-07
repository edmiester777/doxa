//! `#[derive(Actions)]` — an asset's action vocabulary, declared once.
//!
//! An action needs a Cedar name, a capability to gate it, a description
//! for the catalog and the OpenAPI badge, and a sentinel resource for the
//! coarse check. All but the audit category can be worked out from the
//! variant and the enum it sits in, so the common case is a bare list of
//! variants with doc comments, and `#[action(…)]` appears only where a
//! default is wrong.
//!
//! What it emits, for `enum SourceAction { Read, Delete }`:
//!
//! - `mod source_action` holding one marker struct per variant, each a
//!   full capability declaration — so it registers in the catalog like
//!   any `#[capability]` and can be named as `Granted<Cap<…>>`.
//! - `SourceAction::ACTIONS`, the table `Granting::ACTIONS` wants.
//! - `SourceAction::ALL` and `as_static`, so the enum is usable as a
//!   value too.
//!
//! Deliberately no `impl Granting`: an asset's loader and context are its
//! own, and a resource that is generic over a descriptor rather than a
//! concrete struct is not something a derive can attach to at all.
//! Wiring is one line: `const ACTIONS = SourceAction::ACTIONS;`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{Attribute, Data, DeriveInput, Fields, Ident, LitStr, Visibility};

use crate::capability::{declare, CheckArgs};

/// Container-level `#[actions(…)]`. Every field overrides a default that
/// is otherwise read off the enum's name.
#[derive(Default)]
struct Container {
    resource: Option<LitStr>,
    prefix: Option<LitStr>,
    entity_type: Option<LitStr>,
    entity_id: Option<LitStr>,
}

/// Variant-level `#[action(…)]`. Present only where a default is wrong.
#[derive(Default)]
struct Variant {
    name: Option<LitStr>,
    capability: Option<LitStr>,
    description: Option<LitStr>,
    event: Option<LitStr>,
    entity_type: Option<LitStr>,
    entity_id: Option<LitStr>,
    instance_only: bool,
}

/// The Cedar id of the sentinel resource a coarse check asks about.
///
/// A coarse gate runs before anything is loaded, so there is no object to
/// name and the id is always a constant. The tenant reaches
/// `PolicyExtension::build_resource_uid` as its own argument, so this
/// says only *which* collection, never whose.
const DEFAULT_ENTITY_ID: &str = "collection";

pub fn expand(input: TokenStream) -> syn::Result<TokenStream> {
    let input: DeriveInput = syn::parse2(input)?;

    let Data::Enum(data) = &input.data else {
        return Err(syn::Error::new(
            input.span(),
            "`Actions` describes a vocabulary of actions, so it derives on an enum",
        ));
    };

    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(
            input.generics.span(),
            "`Actions` cannot derive on a generic enum: every action resolves to a `'static` \
             capability, which a type parameter has no way to supply",
        ));
    }

    let container = parse_container(&input.attrs)?;
    let enum_name = &input.ident;
    let vis = &input.vis;

    // `SourceAction` describes `Source`. Nothing left after stripping
    // means the name was only the suffix, so keep it whole.
    let resource = match &container.resource {
        Some(lit) => lit.value(),
        None => {
            let name = enum_name.to_string();
            let stripped = name
                .strip_suffix("Actions")
                .or_else(|| name.strip_suffix("Action"))
                .unwrap_or(&name);
            if stripped.is_empty() {
                name.clone()
            } else {
                stripped.to_owned()
            }
        }
    };

    let prefix = match &container.prefix {
        Some(lit) => lit.value(),
        None => snake_case(&resource),
    };
    let entity_type = match &container.entity_type {
        Some(lit) => lit.value(),
        None => format!("{resource}Collection"),
    };
    let entity_id = match &container.entity_id {
        Some(lit) => lit.value(),
        None => DEFAULT_ENTITY_ID.to_owned(),
    };

    let module = Ident::new(&snake_case(&enum_name.to_string()), enum_name.span());

    let mut markers = Vec::new();
    let mut rows = Vec::new();
    let mut arms = Vec::new();
    let mut all = Vec::new();
    // Cedar action name -> the variant that claimed it, so a repeat can
    // point at both ends.
    let mut claimed: Vec<(String, Ident)> = Vec::new();

    for variant in &data.variants {
        if !matches!(variant.fields, Fields::Unit) {
            return Err(syn::Error::new(
                variant.span(),
                "an action carries no data: every variant must be a unit variant",
            ));
        }

        let ident = &variant.ident;
        let parsed = parse_variant(&variant.attrs)?;

        let action = match &parsed.name {
            Some(lit) => lit.value(),
            None => snake_case(&ident.to_string()),
        };

        // A coarse gate has only the action to decide on, so two rows
        // naming one action are not two permissions — the first shadows
        // the second, and the second's capability is never checked
        // despite looking enforced. Reject it here, where the span can
        // name the variant; `doxa::auth::distinct` catches the same
        // mistake in a hand-written table.
        if let Some((_, first)) = claimed.iter().find(|(name, _)| name == &action) {
            return Err(syn::Error::new(
                ident.span(),
                format!(
                    "`{first}` already declares the action `{action}`, so this row \
                     would never be reached. A coarse gate cannot tell two \
                     capabilities over one action apart: give them different \
                     actions, or keep one",
                ),
            ));
        }
        claimed.push((action.clone(), ident.clone()));

        arms.push(quote!(Self::#ident => #action));
        all.push(quote!(Self::#ident));

        let event = match &parsed.event {
            // The audit vocabulary is the application's to define —
            // `doxa_audit::AuditEventType` says so — so this is the one
            // field with no defensible default.
            Some(lit) => quote!(.event(#lit)),
            None => quote!(),
        };

        if parsed.instance_only {
            rows.push(quote! {
                ::doxa::auth::Action::new(#action) #event
            });
            continue;
        }

        let cap_name = match &parsed.capability {
            Some(lit) => lit.value(),
            None => format!("{prefix}.{action}"),
        };
        let description = parsed
            .description
            .clone()
            .map(|lit| lit.value())
            .or_else(|| doc_comment(&variant.attrs))
            .unwrap_or_else(|| format!("{action} on {resource}"));

        let check = CheckArgs {
            action: LitStr::new(&action, ident.span()),
            entity_type: LitStr::new(
                parsed
                    .entity_type
                    .as_ref()
                    .map(|lit| lit.value())
                    .unwrap_or_else(|| entity_type.clone())
                    .as_str(),
                ident.span(),
            ),
            entity_id: LitStr::new(
                parsed
                    .entity_id
                    .as_ref()
                    .map(|lit| lit.value())
                    .unwrap_or_else(|| entity_id.clone())
                    .as_str(),
                ident.span(),
            ),
        };

        let declaration = declare(
            ident,
            &LitStr::new(&cap_name, ident.span()),
            &LitStr::new(&description, ident.span()),
            std::slice::from_ref(&check),
        );

        let marker_doc = format!("The `{cap_name}` capability.");
        let marker_vis = module_vis(vis);
        markers.push(quote! {
            #[doc = #marker_doc]
            #marker_vis struct #ident;
            #declaration
        });

        rows.push(quote! {
            ::doxa::auth::Action::new(#action)
                .capability(<#module::#ident as ::doxa::policy::Capable>::CAPABILITY)
                #event
        });
    }

    let module_doc = format!(
        "Capability markers for [`{enum_name}`], one per action.\n\n\
         Each is a full capability declaration — it registers in the \
         catalog and can be named as `Granted<Cap<{module}::…>>`."
    );

    Ok(quote! {
        #[doc = #module_doc]
        #vis mod #module {
            #(#markers)*
        }

        impl #enum_name {
            /// Every action this asset permits, as `Granting::ACTIONS`
            /// takes it.
            pub const ACTIONS: &'static [::doxa::auth::Action] = &[#(#rows),*];

            /// Every variant, in declaration order.
            pub const ALL: &'static [Self] = &[#(#all),*];

            /// The Cedar action name this variant stands for.
            pub const fn as_static(&self) -> &'static str {
                match self {
                    #(#arms),*
                }
            }
        }
    })
}

/// A marker inside the generated module needs to be at least as visible
/// as the module itself, and `pub` inside a private module is still
/// private.
fn module_vis(vis: &Visibility) -> TokenStream {
    match vis {
        Visibility::Inherited => quote!(),
        _ => quote!(pub),
    }
}

fn parse_container(attrs: &[Attribute]) -> syn::Result<Container> {
    let mut out = Container::default();

    for attr in attrs.iter().filter(|a| a.path().is_ident("actions")) {
        attr.parse_nested_meta(|meta| {
            let target = if meta.path.is_ident("resource") {
                &mut out.resource
            } else if meta.path.is_ident("prefix") {
                &mut out.prefix
            } else if meta.path.is_ident("entity_type") {
                &mut out.entity_type
            } else if meta.path.is_ident("entity_id") {
                &mut out.entity_id
            } else {
                return Err(meta.error(
                    "unknown `actions` option; expected `resource`, `prefix`, `entity_type` or \
                     `entity_id`",
                ));
            };
            *target = Some(meta.value()?.parse()?);
            Ok(())
        })?;
    }

    Ok(out)
}

fn parse_variant(attrs: &[Attribute]) -> syn::Result<Variant> {
    let mut out = Variant::default();

    for attr in attrs.iter().filter(|a| a.path().is_ident("action")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("instance_only") {
                out.instance_only = true;
                return Ok(());
            }

            let target = if meta.path.is_ident("name") {
                &mut out.name
            } else if meta.path.is_ident("capability") {
                &mut out.capability
            } else if meta.path.is_ident("description") {
                &mut out.description
            } else if meta.path.is_ident("event") {
                &mut out.event
            } else if meta.path.is_ident("entity_type") {
                &mut out.entity_type
            } else if meta.path.is_ident("entity_id") {
                &mut out.entity_id
            } else {
                return Err(meta.error(
                    "unknown `action` option; expected `name`, `capability`, `description`, \
                     `event`, `entity_type`, `entity_id` or `instance_only`",
                ));
            };
            *target = Some(meta.value()?.parse()?);
            Ok(())
        })?;
    }

    if out.instance_only && out.capability.is_some() {
        return Err(syn::Error::new(
            attrs
                .iter()
                .find(|a| a.path().is_ident("action"))
                .map(|a| a.span())
                .unwrap_or_else(proc_macro2::Span::call_site),
            "`instance_only` means there is no coarse capability, so naming one contradicts it",
        ));
    }

    Ok(out)
}

/// The variant's doc comment, as the capability description. Lines are
/// joined with a space: a description is one line in a catalog listing
/// and in an OpenAPI badge, however it was written.
fn doc_comment(attrs: &[Attribute]) -> Option<String> {
    let mut lines = Vec::new();

    for attr in attrs.iter().filter(|a| a.path().is_ident("doc")) {
        let syn::Meta::NameValue(nv) = &attr.meta else {
            continue;
        };
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(text),
            ..
        }) = &nv.value
        else {
            continue;
        };
        let text = text.value();
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            lines.push(trimmed.to_owned());
        }
    }

    if lines.is_empty() {
        return None;
    }

    // A trailing full stop reads as prose but not as a catalog entry,
    // which sits beside a name in a table.
    let joined = lines.join(" ");
    Some(joined.trim_end_matches('.').to_owned())
}

/// `ReadSource` -> `read_source`. Runs of capitals stay together, so
/// `ReadURL` is `read_url` rather than `read_u_r_l`.
fn snake_case(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len() + 4);

    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            let starts_word = i > 0
                && (!chars[i - 1].is_uppercase()
                    || chars.get(i + 1).is_some_and(|next| next.is_lowercase()));
            if starts_word {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snake_case_splits_on_word_starts() {
        assert_eq!(snake_case("Read"), "read");
        assert_eq!(snake_case("ReadSource"), "read_source");
        assert_eq!(snake_case("SourceAction"), "source_action");
        assert_eq!(snake_case("ReadURL"), "read_url");
        assert_eq!(snake_case("URLRead"), "url_read");
        assert_eq!(snake_case("already_snake"), "already_snake");
    }

    fn expand_ok(input: TokenStream) -> String {
        expand(input).expect("expands").to_string()
    }

    #[test]
    fn defaults_come_off_the_enum_name() {
        let out = expand_ok(quote! {
            pub enum SourceAction {
                /// List and view data source definitions.
                Read,
            }
        });

        assert!(out.contains(r#"name : "source.read""#), "{out}");
        assert!(
            out.contains(r#"description : "List and view data source definitions""#),
            "{out}",
        );
        assert!(out.contains(r#"entity_type : "SourceCollection""#), "{out}");
        assert!(out.contains(r#"entity_id : "collection""#), "{out}");
        assert!(out.contains("pub mod source_action"), "{out}");
    }

    #[test]
    fn the_container_overrides_every_default() {
        let out = expand_ok(quote! {
            #[actions(resource = "Source", prefix = "sources", entity_id = "tenant")]
            pub enum SourceAction {
                Delete,
            }
        });

        assert!(out.contains(r#"name : "sources.delete""#), "{out}");
        assert!(out.contains(r#"entity_id : "tenant""#), "{out}");
    }

    #[test]
    fn instance_only_declares_no_capability() {
        let out = expand_ok(quote! {
            pub enum WidgetAction {
                #[action(instance_only)]
                Ping,
            }
        });

        assert!(!out.contains("CapabilityCheck"), "{out}");
        assert!(!out.contains("pub struct Ping"), "{out}");
        assert!(out.contains(r#"Action :: new ("ping")"#), "{out}");
        // The row is the whole of it: no `.capability(…)` to resolve.
        assert!(!out.contains(". capability ("), "{out}");
    }

    #[test]
    fn a_data_carrying_variant_is_refused() {
        let err = expand(quote! {
            enum WidgetAction {
                Read(String),
            }
        })
        .expect_err("actions carry no data");
        assert!(err.to_string().contains("unit variant"));
    }

    /// Two rows over one Cedar action would leave the second's
    /// capability declared, catalogued, and never checked.
    #[test]
    fn a_repeated_action_is_refused() {
        let err = expand(quote! {
            enum EntityAction {
                #[action(name = "admin_write")]
                Write,
                #[action(name = "admin_write")]
                Delete,
            }
        })
        .expect_err("one action, two rows");
        let message = err.to_string();
        assert!(message.contains("`Write` already declares"), "{message}");
        assert!(message.contains("admin_write"), "{message}");
    }

    /// The collision is on the Cedar action, not the variant name, so
    /// two differently-named variants that default to one action are the
    /// same mistake.
    #[test]
    fn a_repeat_through_defaults_is_refused() {
        let err = expand(quote! {
            enum WidgetAction {
                Read,
                #[action(name = "read")]
                View,
            }
        })
        .expect_err("both spell `read`");
        assert!(err.to_string().contains("`Read` already declares"));
    }

    #[test]
    fn a_struct_is_refused() {
        let err = expand(quote! {
            struct WidgetAction;
        })
        .expect_err("not an enum");
        assert!(err.to_string().contains("derives on an enum"));
    }
}
