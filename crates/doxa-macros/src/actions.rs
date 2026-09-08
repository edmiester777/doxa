//! `#[derive(Actions)]` — an asset's action vocabulary, declared once.
//!
//! An action needs a Cedar name, a capability to gate it, a description
//! for the catalog and the OpenAPI badge, and a resource for the
//! coarse check. All but the audit category can be worked out from the
//! variant and the enum it sits in, so the common case is a bare list of
//! variants with doc comments, and `#[action(…)]` appears only where a
//! default is wrong.
//!
//! What it emits, for `enum SourceAction { Read, Delete }`:
//!
//! - `mod source_action` holding one marker struct per variant. Each
//!   implements `DeclaredAction`, so it can be handed to
//!   `AuthorizeLoaded::authorize` and the asset's vocabulary is checked at
//!   build time rather than at request time. Where the variant declares a
//!   capability the marker carries that too, registering in the catalog
//!   like any `#[capability]` and namable as `Granted<Cap<…>>`.
//! - One `Action` const per variant, registered so `doxa::auth::actions()`
//!   can answer without a hand-maintained list.
//! - `impl ActionTable for SourceAction`, holding the table
//!   `Granting::ACTIONS` wants, plus `SourceAction::ACTIONS` forwarding to
//!   it. The inherent const is what the one-line wiring names; the trait is
//!   what code generic over a vocabulary can bound on.
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
use syn::{Attribute, Data, DeriveInput, Expr, Fields, Ident, LitStr, Path};

use crate::capability::{declare, parse_entity_id, CheckArgs, EntityId};

/// Container-level `#[actions(…)]`. Every field overrides a default that
/// is otherwise read off the enum's name.
#[derive(Default)]
struct Container {
    resource: Option<LitStr>,
    prefix: Option<LitStr>,
    entity_type: Option<LitStr>,
    entity_id: Option<EntityId>,
}

/// Variant-level `#[action(…)]`. Present only where a default is wrong.
#[derive(Default)]
struct Variant {
    name: Option<LitStr>,
    capability: Option<LitStr>,
    /// An existing `Capable` marker to gate on, rather than a new one to
    /// declare. Named as a path because it is a type that already exists.
    capable: Option<Path>,
    description: Option<LitStr>,
    /// Any `&'static str` const expression, so a variant of the
    /// application's own event enum can be named rather than spelled.
    event: Option<Expr>,
    entity_type: Option<LitStr>,
    entity_id: Option<EntityId>,
    instance_only: bool,
}

/// The Cedar id a coarse check asks about, when the enum does not say.
///
/// A coarse gate runs before anything is loaded, so there is no object to
/// name: the collection is the default, and it says *which* one rather
/// than whose. An asset whose collections are per-tenant writes
/// `#[actions(entity_id = tenant)]`, and doxa substitutes the request's
/// tenant rather than asking the consumer's UID builder to.
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
    let entity_id = container
        .entity_id
        .clone()
        .unwrap_or_else(|| EntityId::literal(DEFAULT_ENTITY_ID, enum_name.span()));

    let module = Ident::new(&snake_case(&enum_name.to_string()), enum_name.span());

    let mut markers = Vec::new();
    let mut consts = Vec::new();
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
            // field with no defensible default. Taken as an expression
            // rather than a string so `EventType::DataAccess.as_static()`
            // is checked, where `"data_acess"` would compile and file
            // every event of this action under a category nothing reads.
            Some(expr) => quote!(.event(#expr)),
            None => quote!(),
        };

        // The coarse half, which is the only part a variant can opt out
        // of: an `instance_only` action has no capability, and a
        // `capable` one gates on a capability that already exists.
        // Minting a second marker over that name would put two entries in
        // the catalog and leave whichever the routes did not name looking
        // enforced.
        let (capability, declaration, cap_name) = if parsed.instance_only {
            (quote!(), quote!(), None)
        } else if let Some(path) = &parsed.capable {
            (
                quote!(.capability(<#path as ::doxa::policy::Capable>::CAPABILITY)),
                quote!(),
                None,
            )
        } else {
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
                entity_id: parsed
                    .entity_id
                    .clone()
                    .unwrap_or_else(|| entity_id.clone()),
            };

            let declaration = declare(
                ident,
                &LitStr::new(&cap_name, ident.span()),
                &LitStr::new(&description, ident.span()),
                std::slice::from_ref(&check),
            );

            (
                quote!(.capability(<#module::#ident as ::doxa::policy::Capable>::CAPABILITY)),
                declaration,
                Some(cap_name),
            )
        };

        // A const rather than an inline row, because a registration needs
        // something with an address. `ACTIONS` then points at the same
        // value the catalog holds, so the two cannot describe one action
        // differently.
        //
        // Emitted beside the enum rather than inside the module: `event`
        // is an arbitrary expression and `capable` an arbitrary path, and
        // both are written where the enum is. Resolving them one module
        // deeper would break every table that names its own event enum.
        //
        // Named after the enum as well as the variant, because that is the
        // scope it lands in: two vocabularies in one module may each have
        // a `Read`, and they are different actions on different assets.
        let row_const = Ident::new(&format!("_DOXA_ACTION_{enum_name}_{ident}"), ident.span());

        let marker_doc = match &cap_name {
            Some(cap) => format!("The `{action}` action, and the `{cap}` capability."),
            None => format!("The `{action}` action."),
        };

        markers.push(quote! {
            #[doc = #marker_doc]
            pub struct #ident;

            impl ::doxa::auth::DeclaredAction for #ident {
                const ACTION: &'static str = #action;
            }

            #declaration
        });

        consts.push(quote! {
            #[doc(hidden)]
            #[allow(non_upper_case_globals)]
            const #row_const: ::doxa::auth::Action =
                ::doxa::auth::Action::new(#action) #capability #event;

            // Declaring the action is what puts it in the catalog, so
            // `doxa::auth::actions()` can answer without anyone
            // maintaining a list. Expands to nothing without the
            // `catalog` feature.
            ::doxa::auth::inventory::submit! { &#row_const }
        });

        rows.push(quote!(#row_const));
    }

    let module_doc = format!(
        "Action markers for [`{enum_name}`], one per variant.\n\n\
         Each implements `DeclaredAction`, so passing one to \
         `AuthorizeLoaded::authorize` is checked against the asset's \
         vocabulary at build time. Where the variant declares a \
         capability the marker carries that too — it registers in the \
         catalog and can be named as `Granted<Cap<{module}::…>>`."
    );
    let markers = quote! {
        #[doc = #module_doc]
        #vis mod #module {
            #(#markers)*
        }
    };

    Ok(quote! {
        #markers

        #(#consts)*

        impl ::doxa::auth::ActionTable for #enum_name {
            const ACTIONS: &'static [::doxa::auth::Action] = &[#(#rows),*];
        }

        impl #enum_name {
            /// Every action this asset permits, as `Granting::ACTIONS`
            /// takes it.
            ///
            /// The same table as `ActionTable::ACTIONS` and not a copy of
            /// it, spelled without the trait so the common wiring needs no
            /// import.
            pub const ACTIONS: &'static [::doxa::auth::Action] =
                <Self as ::doxa::auth::ActionTable>::ACTIONS;

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

fn parse_container(attrs: &[Attribute]) -> syn::Result<Container> {
    let mut out = Container::default();

    for attr in attrs.iter().filter(|a| a.path().is_ident("actions")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("entity_id") {
                out.entity_id = Some(parse_entity_id(meta.value()?)?);
                return Ok(());
            }

            let target = if meta.path.is_ident("resource") {
                &mut out.resource
            } else if meta.path.is_ident("prefix") {
                &mut out.prefix
            } else if meta.path.is_ident("entity_type") {
                &mut out.entity_type
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

            // A type, not a string: the marker exists already, and
            // naming it as a path is what makes a typo a resolution
            // error rather than a silently duplicated catalog entry.
            if meta.path.is_ident("capable") {
                out.capable = Some(meta.value()?.parse::<Path>()?);
                return Ok(());
            }

            if meta.path.is_ident("event") {
                out.event = Some(meta.value()?.parse::<Expr>()?);
                return Ok(());
            }

            if meta.path.is_ident("entity_id") {
                out.entity_id = Some(parse_entity_id(meta.value()?)?);
                return Ok(());
            }

            let target = if meta.path.is_ident("name") {
                &mut out.name
            } else if meta.path.is_ident("capability") {
                &mut out.capability
            } else if meta.path.is_ident("description") {
                &mut out.description
            } else if meta.path.is_ident("entity_type") {
                &mut out.entity_type
            } else {
                return Err(meta.error(
                    "unknown `action` option; expected `name`, `capability`, `capable`, \
                     `description`, `event`, `entity_type`, `entity_id` or `instance_only`",
                ));
            };
            *target = Some(meta.value()?.parse()?);
            Ok(())
        })?;
    }

    let span = || {
        attrs
            .iter()
            .find(|a| a.path().is_ident("action"))
            .map(|a| a.span())
            .unwrap_or_else(proc_macro2::Span::call_site)
    };

    if out.instance_only && (out.capability.is_some() || out.capable.is_some()) {
        return Err(syn::Error::new(
            span(),
            "`instance_only` means there is no coarse capability, so naming one contradicts it",
        ));
    }

    if out.capability.is_some() && out.capable.is_some() {
        return Err(syn::Error::new(
            span(),
            "`capability` declares a new capability and `capable` gates on one that already \
             exists; naming both would catalogue a second entry over the same action and leave \
             it looking enforced. Keep whichever is right",
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

    fn expand_err(input: TokenStream) -> String {
        expand(input).expect_err("rejected").to_string()
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
        assert!(
            out.contains(r#"ResourceId :: Literal ("collection")"#),
            "{out}",
        );
        assert!(out.contains("pub mod source_action"), "{out}");
    }

    /// The tenant is written as a bare word, not as the string
    /// `"tenant"`. It names no id — it says there is one to substitute,
    /// and doxa does that before the consumer's UID builder is reached.
    #[test]
    fn the_container_overrides_every_default() {
        let out = expand_ok(quote! {
            #[actions(resource = "Source", prefix = "sources", entity_id = tenant)]
            pub enum SourceAction {
                Delete,
            }
        });

        assert!(out.contains(r#"name : "sources.delete""#), "{out}");
        assert!(out.contains("ResourceId :: Tenant"), "{out}");
    }

    /// A misspelling is caught at the attribute rather than becoming a
    /// literal id that matches nothing — which is what a bare string
    /// would have silently produced.
    #[test]
    fn an_unknown_entity_id_word_is_refused() {
        let message = expand_err(quote! {
            #[actions(entity_id = tennant)]
            pub enum SourceAction {
                Read,
            }
        });

        assert!(message.contains("tennant"), "{message}");
        assert!(message.contains("bare word `tenant`"), "{message}");
    }

    /// No capability, but still a marker: the action exists, so there is
    /// something to name at a call site and something to check it
    /// against. Only the coarse half is absent.
    #[test]
    fn instance_only_declares_no_capability() {
        let out = expand_ok(quote! {
            pub enum WidgetAction {
                #[action(instance_only)]
                Ping,
            }
        });

        assert!(!out.contains("CapabilityCheck"), "{out}");
        assert!(out.contains("pub struct Ping"), "{out}");
        assert!(
            out.contains(r#"const ACTION : & 'static str = "ping""#),
            "{out}"
        );
        assert!(out.contains(r#"Action :: new ("ping")"#), "{out}");
        // The row is the whole of it: no `.capability(…)` to resolve.
        assert!(!out.contains(". capability ("), "{out}");
    }

    /// Every variant reaches the catalog, including the two that declare
    /// no capability — which is the gap this closes. A capability-derived
    /// list can see neither.
    #[test]
    fn every_variant_registers_its_action() {
        let out = expand_ok(quote! {
            pub enum SourceAction {
                Read,
                #[action(capable = catalog::SourcesArchive)]
                Archive,
                #[action(instance_only)]
                Ping,
            }
        });

        for variant in ["Read", "Archive", "Ping"] {
            let row = format!("_DOXA_ACTION_SourceAction_{variant}");
            assert!(out.contains(&row), "{variant} has no action const: {out}");
            assert!(
                out.contains(&format!("submit ! {{ & {row} }}")),
                "{variant} is not registered: {out}",
            );
        }
    }

    /// The action const lands beside the enum, not inside the module, so
    /// its name has to carry the enum too. Two vocabularies in one module
    /// each having a `Read` is ordinary — they are different actions on
    /// different assets — and a shared const name would be a redefinition
    /// the user never wrote.
    #[test]
    fn two_vocabularies_in_one_module_do_not_collide() {
        let sources = expand_ok(quote! {
            pub enum SourceAction { Read }
        });
        let widgets = expand_ok(quote! {
            pub enum WidgetAction { Read }
        });

        assert!(
            sources.contains("_DOXA_ACTION_SourceAction_Read"),
            "{sources}"
        );
        assert!(
            widgets.contains("_DOXA_ACTION_WidgetAction_Read"),
            "{widgets}"
        );
    }

    /// The table lands in the trait impl, and the inherent const forwards
    /// to it rather than repeating the array. Two arrays would be two
    /// tables, and a generic caller and a direct one could disagree about
    /// what the asset permits.
    #[test]
    fn the_table_is_a_trait_impl_the_inherent_const_forwards_to() {
        let out = expand_ok(quote! {
            pub enum SourceAction { Read }
        });

        assert!(
            out.contains("impl :: doxa :: auth :: ActionTable for SourceAction"),
            "{out}",
        );
        assert!(
            out.contains(
                "pub const ACTIONS : & 'static [:: doxa :: auth :: Action] = \
                 < Self as :: doxa :: auth :: ActionTable > :: ACTIONS"
            ),
            "{out}",
        );
        // The rows are gathered into an array exactly once. A second one
        // would be the inherent const having been left as a copy.
        assert_eq!(
            out.matches("& [_DOXA_ACTION_SourceAction_Read]").count(),
            1,
            "{out}",
        );
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

    /// `capable` gates on a marker that exists; it must not also declare
    /// one, or the catalog would carry an entry no route names.
    #[test]
    fn capable_references_without_declaring() {
        let out = expand_ok(quote! {
            pub enum SourceAction {
                #[action(capable = catalog::SourcesRead)]
                Read,
            }
        });

        assert!(
            out.contains(
                "< catalog :: SourcesRead as :: doxa :: policy :: Capable > :: CAPABILITY"
            ),
            "{out}",
        );
        assert!(!out.contains("CapabilityCheck"), "{out}");
        // The action marker is still emitted — it is the referenced
        // capability that is not re-declared, not the action.
        assert!(out.contains("pub struct Read"), "{out}");
        assert!(!out.contains("Capable for Read"), "{out}");
    }

    /// The module is emitted even when no variant declares a capability:
    /// every action has a marker now, because every action is something a
    /// call site may need to name and have checked.
    #[test]
    fn an_enum_that_declares_no_capability_still_has_markers() {
        let out = expand_ok(quote! {
            pub enum SourceAction {
                #[action(capable = catalog::SourcesRead)]
                Read,
                #[action(instance_only)]
                Ping,
            }
        });

        assert!(out.contains("mod source_action"), "{out}");
        assert!(out.contains("pub struct Read"), "{out}");
        assert!(out.contains("pub struct Ping"), "{out}");
        assert!(!out.contains("CapabilityCheck"), "{out}");
    }

    #[test]
    fn declaring_and_referencing_one_capability_is_refused() {
        let message = expand_err(quote! {
            pub enum SourceAction {
                #[action(capability = "sources.read", capable = catalog::SourcesRead)]
                Read,
            }
        });

        assert!(message.contains("Keep whichever is right"), "{message}");
    }

    #[test]
    fn an_instance_only_action_may_not_name_an_existing_capability() {
        let message = expand_err(quote! {
            pub enum SourceAction {
                #[action(instance_only, capable = catalog::SourcesRead)]
                Ping,
            }
        });

        assert!(message.contains("contradicts it"), "{message}");
    }

    /// A string literal is an expression too, so widening `event` to take
    /// one did not invalidate the tables already written against it.
    #[test]
    fn the_event_category_is_still_accepted_as_a_string() {
        let out = expand_ok(quote! {
            pub enum SourceAction {
                #[action(instance_only, event = "data_access")]
                Read,
            }
        });

        assert!(out.contains(r#". event ("data_access")"#), "{out}");
    }

    /// The category is an expression, so an enum variant is checked where
    /// a bare string never was.
    #[test]
    fn the_event_category_may_be_a_const_expression() {
        let out = expand_ok(quote! {
            pub enum SourceAction {
                #[action(instance_only, event = EventType::DataAccess.as_static())]
                Read,
            }
        });

        assert!(
            out.contains(". event (EventType :: DataAccess . as_static ())"),
            "{out}",
        );
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
