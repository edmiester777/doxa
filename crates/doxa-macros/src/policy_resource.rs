//! `#[derive(PolicyResource)]` — Cedar entity identity for a domain type,
//! and optionally the scoped lookup that loads it.
//!
//! One declaration produces the Cedar entity type, the instance id, the
//! attributes policies may reference, and the parent list. The entity
//! type doubles as the audit `resource_type`, so an audit row and the
//! decision that produced it share one string.
//!
//! Identity is usually a field apiece, but not always: a Cedar id can be
//! computed from several columns, and an attribute can be a fact about a
//! row rather than a column on it. `id_with` and `attrs_with` name a
//! method for those, so one awkward attribute does not push a whole type
//! back to a hand-written impl.
//!
//! With the `sea-orm` feature, `#[resource(key)]` and `#[resource(scope)]`
//! emit a [`ScopedRow`] impl as well — the query half, which is the rest
//! of what a route needs before it can decide anything. The key and the
//! Cedar id are deliberately independent: a row addressed by `{model_id}`
//! and the same row addressed by `{name}` are one Cedar entity reached two
//! ways.
//!
//! [`ScopedRow`]: https://docs.rs/doxa-policy/latest/doxa_policy/scoped/trait.ScopedRow.html

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Ident, LitStr, Result, Type};

/// Role a field plays in the generated impls.
enum Role {
    Id,
    Attr(String),
    Parent(LitStr),
    Key,
    Scope,
}

/// Container-level `#[resource(…)]`.
struct Container {
    entity_type: LitStr,
    /// Method producing the Cedar id, when no one field is it.
    id_with: Option<Ident>,
    /// Method producing attributes no field backs.
    attrs_with: Option<Ident>,
}

pub fn expand(input: TokenStream) -> Result<TokenStream> {
    let input: DeriveInput = syn::parse2(input)?;
    let ident = &input.ident;

    let container = container_args(&input)?;
    let entity_type = &container.entity_type;

    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            &input,
            "`PolicyResource` can only be derived for structs",
        ));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new_spanned(
            &data.fields,
            "`PolicyResource` requires named fields",
        ));
    };

    let mut id_field: Option<Ident> = None;
    let mut attrs: Vec<(String, Ident)> = Vec::new();
    let mut parents: Vec<(LitStr, Ident)> = Vec::new();
    let mut key: Option<(Ident, Type)> = None;
    let mut scope: Option<Ident> = None;

    for field in &fields.named {
        let name = field.ident.clone().expect("named field");
        for role in field_roles(field)? {
            match role {
                Role::Id => {
                    if id_field.is_some() {
                        return Err(syn::Error::new_spanned(
                            field,
                            "only one field may be marked `#[resource(id)]`",
                        ));
                    }
                    id_field = Some(name.clone());
                }
                Role::Attr(attr_key) => attrs.push((attr_key, name.clone())),
                Role::Parent(ty) => parents.push((ty, name.clone())),
                Role::Key => {
                    if key.is_some() {
                        return Err(syn::Error::new_spanned(
                            field,
                            "only one field may be marked `#[resource(key)]`: a lookup matches \
                             one column, and a second route to the same row is its own descriptor",
                        ));
                    }
                    key = Some((name.clone(), field.ty.clone()));
                }
                Role::Scope => {
                    if scope.is_some() {
                        return Err(syn::Error::new_spanned(
                            field,
                            "only one field may be marked `#[resource(scope)]`",
                        ));
                    }
                    scope = Some(name.clone());
                }
            }
        }
    }

    let id_body = match (&container.id_with, &id_field) {
        (Some(method), None) => quote!(::std::string::ToString::to_string(&self.#method())),
        (None, Some(field)) => quote!(::std::string::ToString::to_string(&self.#field)),
        (Some(_), Some(field)) => {
            return Err(syn::Error::new(
                field.span(),
                "`id_with` already says what the Cedar id is, so `#[resource(id)]` would be a \
                 second answer to one question: keep whichever is right",
            ))
        }
        (None, None) => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "`PolicyResource` needs an id: mark one field `#[resource(id)]`, or name a \
                 method with `#[resource(id_with = …)]`",
            ))
        }
    };

    let attr_inserts = attrs.iter().map(|(key, field)| {
        quote! {
            __map.insert(
                #key.to_owned(),
                ::doxa::__private::serde_json::to_value(&self.#field)
                    // Fail closed: an unserializable attribute becomes
                    // null, which no equality clause will match.
                    .unwrap_or(::doxa::__private::serde_json::Value::Null),
            );
        }
    });

    // Merged after the field inserts, so the escape hatch wins on a
    // collision: a computed attribute is the deliberate one.
    let attrs_merge = container.attrs_with.as_ref().map(|method| {
        quote! { __map.extend(self.#method()); }
    });

    let parent_pushes = parents.iter().map(|(entity, field)| {
        quote! { __parents.push((#entity, ::std::string::ToString::to_string(&self.#field))); }
    });

    let scoped = scoped_impl(ident, key.as_ref(), scope.as_ref())?;

    Ok(quote! {
        #[automatically_derived]
        impl ::doxa::policy::PolicyResource for #ident {
            const ENTITY_TYPE: &'static str = #entity_type;

            fn resource_id(&self) -> ::std::string::String {
                #id_body
            }

            fn cedar_attrs(
                &self,
            ) -> ::doxa::__private::serde_json::Map<
                ::std::string::String,
                ::doxa::__private::serde_json::Value,
            > {
                let mut __map = ::doxa::__private::serde_json::Map::new();
                #(#attr_inserts)*
                #attrs_merge
                __map
            }

            fn cedar_parents(&self) -> ::std::vec::Vec<(&'static str, ::std::string::String)> {
                let mut __parents = ::std::vec::Vec::new();
                #(#parent_pushes)*
                __parents
            }
        }

        #scoped
    })
}

/// The `ScopedRow` half, when the struct marked both a key and a scope.
///
/// `Entity` and `Column` are named unqualified because `DeriveEntityModel`
/// puts them beside the `Model` this derive is sitting on. That is the
/// whole reason the loader can be generated at all: the table, its columns
/// and the row are one module by construction.
///
/// The feature is checked here rather than as a `#[cfg]` on the emitted
/// impl. A `#[cfg]` would silently produce nothing, and the consumer would
/// meet a missing-impl error at the route rather than an explanation here.
fn scoped_impl(
    ident: &Ident,
    key: Option<&(Ident, Type)>,
    scope: Option<&Ident>,
) -> Result<TokenStream> {
    let (key, scope) =
        match (key, scope) {
            (None, None) => return Ok(quote!()),
            (Some((field, _)), None) => return Err(syn::Error::new(
                field.span(),
                "a key with no scope column would look up across every owner, so a caller could \
                 reach another tenant's row by naming it: mark the owning column \
                 `#[resource(scope)]`",
            )),
            (None, Some(field)) => {
                return Err(syn::Error::new(
                    field.span(),
                    "`scope` narrows a lookup and there is none to narrow: mark the column the \
                 route's key matches `#[resource(key)]`",
                ))
            }
            (Some(key), Some(scope)) => (key, scope),
        };

    let (key_field, key_ty) = key;

    if !cfg!(feature = "sea-orm") {
        return Err(syn::Error::new(
            key_field.span(),
            "`#[resource(key)]` and `#[resource(scope)]` generate a SeaORM `ScopedRow` impl, \
             which needs the `policy-sea-orm` feature on `doxa`",
        ));
    }

    let key_column = column_variant(key_field);
    let scope_column = column_variant(scope);

    Ok(quote! {
        #[automatically_derived]
        impl ::doxa::policy::ScopedRow for #ident {
            type Entity = Entity;
            type Key = #key_ty;

            const KEY_COLUMN:
                <Entity as ::doxa::policy::__private::sea_orm::EntityTrait>::Column =
                Column::#key_column;

            const SCOPE_COLUMN:
                <Entity as ::doxa::policy::__private::sea_orm::EntityTrait>::Column =
                Column::#scope_column;
        }
    })
}

/// `company_id` -> `CompanyId`, matching the `Column` variant
/// `DeriveEntityModel` generates from a field name.
fn column_variant(field: &Ident) -> Ident {
    let raw = field.to_string();
    let name = raw.strip_prefix("r#").unwrap_or(&raw);

    let mut out = String::with_capacity(name.len());
    for part in name.split('_').filter(|part| !part.is_empty()) {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }

    Ident::new(&out, field.span())
}

/// Parse `#[resource(entity_type = "…", id_with = …, attrs_with = …)]`
/// off the struct.
fn container_args(input: &DeriveInput) -> Result<Container> {
    let mut entity_type = None;
    let mut id_with = None;
    let mut attrs_with = None;

    for attr in &input.attrs {
        if !attr.path().is_ident("resource") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("entity_type") {
                entity_type = Some(meta.value()?.parse::<LitStr>()?);
                Ok(())
            } else if meta.path.is_ident("id_with") {
                id_with = Some(meta.value()?.parse::<Ident>()?);
                Ok(())
            } else if meta.path.is_ident("attrs_with") {
                attrs_with = Some(meta.value()?.parse::<Ident>()?);
                Ok(())
            } else {
                Err(meta.error("expected `entity_type`, `id_with` or `attrs_with`"))
            }
        })?;
    }

    let entity_type = entity_type.ok_or_else(|| {
        syn::Error::new_spanned(
            &input.ident,
            "missing `#[resource(entity_type = \"…\")]` on the struct",
        )
    })?;

    Ok(Container {
        entity_type,
        id_with,
        attrs_with,
    })
}

/// Parse `#[resource(id)]` / `#[resource(attr)]` / `#[resource(attr =
/// "key")]` / `#[resource(parent = "Folder")]` / `#[resource(key)]` /
/// `#[resource(scope)]` off one field.
fn field_roles(field: &syn::Field) -> Result<Vec<Role>> {
    let mut roles = Vec::new();
    let default_key = field
        .ident
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();

    for attr in &field.attrs {
        if !attr.path().is_ident("resource") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("id") {
                roles.push(Role::Id);
                Ok(())
            } else if meta.path.is_ident("attr") {
                // Bare `attr` uses the field name; `attr = "x"` renames.
                let key = match meta.value() {
                    Ok(value) => value.parse::<LitStr>()?.value(),
                    Err(_) => default_key.clone(),
                };
                roles.push(Role::Attr(key));
                Ok(())
            } else if meta.path.is_ident("parent") {
                roles.push(Role::Parent(meta.value()?.parse::<LitStr>()?));
                Ok(())
            } else if meta.path.is_ident("key") {
                roles.push(Role::Key);
                Ok(())
            } else if meta.path.is_ident("scope") {
                roles.push(Role::Scope);
                Ok(())
            } else {
                Err(meta
                    .error("expected `id`, `attr`, `parent = \"EntityType\"`, `key` or `scope`"))
            }
        })?;
    }

    Ok(roles)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand_ok(input: TokenStream) -> String {
        expand(input).expect("expands").to_string()
    }

    fn expand_err(input: TokenStream) -> String {
        expand(input).expect_err("rejected").to_string()
    }

    #[test]
    fn a_field_id_reads_straight_off_the_struct() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Widget")]
            struct Widget {
                #[resource(id)]
                name: String,
            }
        });

        assert!(
            out.contains(r#"ENTITY_TYPE : & 'static str = "Widget""#),
            "{out}"
        );
        assert!(out.contains("to_string (& self . name)"), "{out}");
    }

    #[test]
    fn id_with_names_a_method_instead() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Model", id_with = qualified_name)]
            struct Model {
                namespace: String,
                name: String,
            }
        });

        assert!(
            out.contains("to_string (& self . qualified_name ())"),
            "{out}"
        );
    }

    /// Two answers to one question is a mistake worth naming, not a
    /// precedence rule to remember.
    #[test]
    fn an_id_field_and_id_with_together_are_refused() {
        let message = expand_err(quote! {
            #[resource(entity_type = "Model", id_with = qualified_name)]
            struct Model {
                #[resource(id)]
                name: String,
            }
        });

        assert!(
            message.contains("second answer to one question"),
            "{message}"
        );
    }

    #[test]
    fn attrs_with_merges_after_the_field_attrs() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Connection", attrs_with = policy_attrs)]
            struct Model {
                #[resource(id, attr)]
                name: String,
            }
        });

        let inserted = out.find(r#"__map . insert ("name""#).expect("field attr");
        let merged = out.find("__map . extend").expect("computed attrs");
        assert!(
            inserted < merged,
            "the escape hatch must win on a collision: {out}"
        );
    }

    #[test]
    fn a_missing_id_is_refused() {
        let message = expand_err(quote! {
            #[resource(entity_type = "Widget")]
            struct Widget {
                name: String,
            }
        });

        assert!(message.contains("needs an id"), "{message}");
    }

    #[test]
    fn field_names_become_column_variants() {
        assert_eq!(column_variant(&parse_ident("name")), parse_ident("Name"));
        assert_eq!(
            column_variant(&parse_ident("company_id")),
            parse_ident("CompanyId"),
        );
        assert_eq!(
            column_variant(&parse_ident("entity_uid")),
            parse_ident("EntityUid"),
        );
    }

    fn parse_ident(name: &str) -> Ident {
        Ident::new(name, proc_macro2::Span::call_site())
    }

    /// A key that is not confined to an owner is the bug this whole
    /// trait exists to make unwritable.
    #[test]
    fn a_key_without_a_scope_is_refused() {
        let message = expand_err(quote! {
            #[resource(entity_type = "Widget")]
            struct Model {
                #[resource(id, key)]
                name: String,
            }
        });

        assert!(message.contains("across every owner"), "{message}");
    }

    #[test]
    fn a_scope_without_a_key_is_refused() {
        let message = expand_err(quote! {
            #[resource(entity_type = "Widget")]
            struct Model {
                #[resource(id)]
                name: String,
                #[resource(scope)]
                company_id: String,
            }
        });

        assert!(message.contains("none to narrow"), "{message}");
    }

    #[test]
    fn identity_alone_emits_no_loader() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Widget")]
            struct Widget {
                #[resource(id)]
                name: String,
            }
        });

        assert!(!out.contains("ScopedRow"), "{out}");
    }

    #[cfg(feature = "sea-orm")]
    #[test]
    fn a_key_and_a_scope_emit_the_loader() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Connection")]
            struct Model {
                #[resource(id, attr, key)]
                name: String,
                #[resource(parent = "Tenant", scope)]
                company_id: String,
            }
        });

        assert!(
            out.contains("impl :: doxa :: policy :: ScopedRow for Model"),
            "{out}"
        );
        assert!(out.contains("type Key = String"), "{out}");
        assert!(out.contains("Column :: Name"), "{out}");
        assert!(out.contains("Column :: CompanyId"), "{out}");
    }

    /// The route's key and the Cedar id answer different questions, so a
    /// row keyed by its uuid can still name itself something else.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn the_key_is_independent_of_the_id() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Model", id_with = qualified_name)]
            struct Model {
                #[resource(key)]
                id: Uuid,
                #[resource(scope)]
                company_id: String,
            }
        });

        assert!(out.contains("type Key = Uuid"), "{out}");
        assert!(
            out.contains("to_string (& self . qualified_name ())"),
            "{out}"
        );
    }

    #[cfg(not(feature = "sea-orm"))]
    #[test]
    fn a_loader_without_the_feature_names_the_feature() {
        let message = expand_err(quote! {
            #[resource(entity_type = "Connection")]
            struct Model {
                #[resource(id, key)]
                name: String,
                #[resource(scope)]
                company_id: String,
            }
        });

        assert!(message.contains("policy-sea-orm"), "{message}");
    }
}
