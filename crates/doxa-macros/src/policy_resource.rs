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
//! With the `sea-orm` feature, `#[resource(scope)]` emits a
//! [`ScopedTable`] impl — the column every query is confined to, and the
//! column behind each Cedar attribute — and `#[resource(key)]` adds
//! [`ScopedRow`] on top of it, the lookup a route reaches one row by.
//! Marking only the scope is a table nothing addresses by a column, which
//! can still be listed and still have a policy's residual read against it.
//! The key and the Cedar id are deliberately independent: a row addressed
//! by `{model_id}` and the same row addressed by `{name}` are one Cedar
//! entity reached two ways.
//!
//! Both roles also emit the backend-neutral [`fetch`] impls, via
//! `fetch_from_scoped!`. Those are what `#[asset]` reaches, so the SeaORM
//! traits above are one answer to the question rather than the question:
//! a row that is not in a table implements [`fetch`] directly and gets the
//! same generated `Granting`.
//!
//! `#[resource(key)]` is the unnamed lookup and there is one per struct,
//! which runs out for a row reached three ways. `#[resource(key(Name))]`
//! names one instead: a column may carry several names and several columns
//! may carry one, so a composite key and a column serving two routes are
//! the same declaration. Each name emits a `Lookup` marker through
//! `scoped_lookup!`, and a composite additionally gets a key struct with a
//! field per column — plus the `RouteKey` impl for it, which is written
//! here rather than in that macro because the trait belongs to `doxa-auth`
//! and `doxa-policy` does not depend on it.
//!
//! `#[resource(filter = …)]` is a condition every query carries on top of
//! the scope, spliced rather than interpreted. It hangs on the table so
//! that the key lookup, the id lookup, the listing and the residual filter
//! all inherit it — a soft delete applied to three of those four is not a
//! compile error, it is a deleted row coming back on the fourth.
//!
//! [`ScopedTable`]: https://docs.rs/doxa-policy/latest/doxa_policy/scoped/trait.ScopedTable.html
//! [`ScopedRow`]: https://docs.rs/doxa-policy/latest/doxa_policy/scoped/trait.ScopedRow.html
//! [`fetch`]: https://docs.rs/doxa-policy/latest/doxa_policy/fetch/index.html

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Expr, Fields, Ident, LitStr, Result, Type};

/// Role a field plays in the generated impls.
enum Role {
    Id,
    Attr(String),
    Parent(LitStr),
    Key,
    /// One column of the named lookup `#[resource(key(Name))]` declares.
    /// A field may carry several, and several fields may carry the same
    /// one — which is how a column serves more than one way in, and how a
    /// composite key is spelled.
    NamedKey(Ident),
    Scope,
}

/// The columns one named lookup matches, in declaration order.
type NamedLookup = (Ident, Vec<(Ident, Type)>);

/// Container-level `#[resource(…)]`.
struct Container {
    entity_type: LitStr,
    /// Method producing the Cedar id, when no one field is it.
    id_with: Option<Ident>,
    /// Method producing attributes no field backs.
    attrs_with: Option<Ident>,
    /// Entity type this resource is `in` by virtue of the request.
    tenant_parent: Option<LitStr>,
    /// Conditions every query against this table carries, on top of the
    /// scope. Spliced verbatim and `AND`ed, so they are whatever SeaORM
    /// accepts rather than a vocabulary this derive has to keep up with.
    filters: Vec<Expr>,
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
    let mut named: Vec<NamedLookup> = Vec::new();
    let mut scope: Option<Ident> = None;
    // What the identifier columns are called, for the `key = pk` route.
    // Read off SeaORM's own marker rather than `#[resource(…)]`, because a
    // primary key is a fact about the table that the row has already
    // stated once. Plural for the composite key, whose `PrimaryKeyOf` is a
    // tuple and whose route therefore has a segment each.
    let mut primary_key: Vec<Ident> = Vec::new();

    for field in &fields.named {
        let name = field.ident.clone().expect("named field");
        if is_primary_key(field) {
            primary_key.push(name.clone());
        }
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
                            "only one field may be marked `#[resource(key)]`: the unnamed lookup \
                             matches one column. For a composite key, or for a second way into \
                             the same row, name them — `#[resource(key(FindByPair))]` on each \
                             column that takes part",
                        ));
                    }
                    key = Some((name.clone(), field.ty.clone()));
                }
                Role::NamedKey(lookup) => {
                    let columns = match named.iter_mut().find(|(existing, _)| *existing == lookup) {
                        Some((_, columns)) => columns,
                        None => {
                            named.push((lookup.clone(), Vec::new()));
                            &mut named.last_mut().expect("just pushed").1
                        }
                    };
                    if columns.iter().any(|(column, _)| *column == name) {
                        return Err(syn::Error::new(
                            lookup.span(),
                            "this column is already part of that lookup; naming it twice would \
                             match it against itself and widen the key by a segment no route \
                             supplies",
                        ));
                    }
                    columns.push((name.clone(), field.ty.clone()));
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

    let scoped = scoped_impl(
        ident,
        key.as_ref(),
        &primary_key,
        &named,
        scope.as_ref(),
        &container.filters,
        &attrs,
    )?;

    // Not a field: the tenant is a fact about the request, so there may
    // be no column to read and a nullable one would answer a different
    // question — a row belonging to no tenant is still decided about
    // inside the asking one.
    let tenant_parent = match &container.tenant_parent {
        Some(ty) => quote!(const TENANT_PARENT: ::std::option::Option<&'static str> = Some(#ty);),
        None => quote!(),
    };

    Ok(quote! {
        #[automatically_derived]
        impl ::doxa::policy::PolicyResource for #ident {
            const ENTITY_TYPE: &'static str = #entity_type;
            #tenant_parent

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

/// The SeaORM half: `ScopedTable` from the scope column, and `ScopedRow`
/// on top of it when the struct also marked a key.
///
/// The two are emitted separately because the struct can supply one
/// without the other. A scope column and no key is a table whose rows have
/// an owner but which no route addresses by a column — a name resolved
/// through logic, an id that means nothing to a policy — and it still
/// wants listing and still wants its attributes to have columns. A key
/// with no scope is the reverse and is refused: it would look up across
/// every owner.
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
    primary_key: &[Ident],
    named: &[NamedLookup],
    scope: Option<&Ident>,
    filters: &[Expr],
    attrs: &[(String, Ident)],
) -> Result<TokenStream> {
    let scope = match scope {
        Some(scope) => scope,
        None => {
            // Every one of these needs the owning column, and each is worth
            // its own diagnosis: they are three different things a struct
            // can ask for that all resolve to "mark the scope".
            if let Some((field, _)) = key {
                return Err(syn::Error::new(
                    field.span(),
                    "a key with no scope column would look up across every owner, so a caller \
                     could reach another tenant's row by naming it: mark the owning column \
                     `#[resource(scope)]`",
                ));
            }
            if let Some((lookup, _)) = named.first() {
                return Err(syn::Error::new(
                    lookup.span(),
                    "a named lookup with no scope column would look up across every owner, so a \
                     caller could reach another tenant's row by naming it: mark the owning \
                     column `#[resource(scope)]`",
                ));
            }
            if let Some(filter) = filters.first() {
                return Err(syn::Error::new_spanned(
                    filter,
                    "`filter` is a condition on the generated `ScopedTable`, which is what a \
                     scope column produces: mark the owning column `#[resource(scope)]`",
                ));
            }
            return Ok(quote!());
        }
    };

    if !cfg!(feature = "sea-orm") {
        return Err(syn::Error::new(
            scope.span(),
            "`#[resource(scope)]` generates a SeaORM `ScopedTable` impl, which needs the \
             `policy-sea-orm` feature on `doxa`",
        ));
    }

    let scope_column = column_variant(scope);

    // The attributes a policy may name, paired with the columns they sit
    // in. Written from the same `#[resource(attr)]` fields that build
    // `cedar_attrs`, so a policy cannot mention an attribute the filter
    // half has never heard of.
    //
    // An attribute from `attrs_with` is absent by construction: it is a
    // fact computed about the row rather than a column on it, so there is
    // nothing to put in a `WHERE` clause and the fallthrough refuses it.
    let attr_columns = attrs.iter().map(|(key, field)| {
        let column = column_variant(field);
        quote!(#key => ::std::option::Option::Some(Column::#column),)
    });

    let row = key.map(|(key_field, key_ty)| {
        let key_column = column_variant(key_field);
        quote! {
            #[automatically_derived]
            impl ::doxa::policy::ScopedRow for #ident {
                type Key = #key_ty;

                const KEY_COLUMN:
                    <Entity as ::doxa::policy::__private::sea_orm::EntityTrait>::Column =
                    Column::#key_column;
            }
        }
    });

    // The backend-neutral half, which is what `#[asset]` actually reaches:
    // the SeaORM traits above say how *this* table answers a scoped
    // lookup, and these say that it answers one at all. Emitted here
    // rather than as a blanket impl in `doxa-policy` because a blanket
    // would foreclose a consumer implementing the same traits for a row of
    // their own against some other backend — see `fetch_from_scoped!`.
    //
    // `key` selects the arm: without one there is no `ScopedRow` to build
    // `FetchByKey` from, and the table keeps its id route and its listing.
    //
    // The column names go across with them. They are the field idents this
    // derive already read, and they are what lets a route addressing the
    // row by that column stop repeating the name in a `#[key("…")]`.
    let id_names = primary_key
        .iter()
        .map(|field| LitStr::new(&field.to_string(), field.span()));
    let fetch = match key {
        Some((field, _)) => {
            let key_name = LitStr::new(&field.to_string(), field.span());
            quote! {
                ::doxa::policy::fetch_from_scoped!(
                    #ident, key, id = [#(#id_names),*], key = [#key_name]
                );
            }
        }
        None => quote!(::doxa::policy::fetch_from_scoped!(#ident, id = [#(#id_names),*]);),
    };

    // One marker type per named lookup, each carrying its own key and its
    // own columns. The macro builds every one on `ScopedTable::scoped`, so
    // they all inherit the scope filter and the conditions below — a second
    // way into a row cannot be a way around either.
    let lookups = named.iter().map(|(lookup, columns)| {
        let entries = columns.iter().map(|(field, ty)| {
            let column = column_variant(field);
            quote!(#field: #ty => Column::#column)
        });
        let doc = format!(
            "Reaches [`{ident}`] by {}, within the row's own scope.",
            columns
                .iter()
                .map(|(field, _)| format!("`{field}`"))
                .collect::<Vec<_>>()
                .join(" + "),
        );

        // A single column keeps the bare scalar for its key — the same
        // shape `#[resource(key)]` produces, so a one-segment route reads
        // identically whether its lookup was named or not. Only a composite
        // needs a struct, and only a composite gets one.
        if columns.len() == 1 {
            return quote! {
                ::doxa::policy::scoped_lookup!(
                    #[doc = #doc]
                    #[automatically_derived]
                    pub #lookup for #ident { #(#entries),* }
                );
            };
        }

        let key = Ident::new(&format!("{lookup}Key"), lookup.span());
        let route_key = route_key_impl(&key, columns);

        quote! {
            ::doxa::policy::scoped_lookup!(
                #[doc = #doc]
                #[automatically_derived]
                pub #lookup as #key for #ident { #(#entries),* }
            );

            #route_key
        }
    });

    // Spliced rather than interpreted: `filter` takes whatever SeaORM would
    // accept in a `filter(…)` call, so there is no operator vocabulary here
    // to fall behind the one SeaORM actually has.
    let table_condition = (!filters.is_empty()).then(|| {
        quote! {
            fn table_condition() -> ::std::option::Option<
                ::doxa::policy::__private::sea_orm::Condition,
            > {
                ::std::option::Option::Some(
                    ::doxa::policy::__private::sea_orm::Condition::all()
                        #(.add(#filters))*
                )
            }
        }
    });

    Ok(quote! {
        #[automatically_derived]
        impl ::doxa::policy::ScopedTable for #ident {
            type Entity = Entity;

            const SCOPE_COLUMN:
                <Entity as ::doxa::policy::__private::sea_orm::EntityTrait>::Column =
                Column::#scope_column;

            fn column_for_attr(
                __attr: &str,
            ) -> ::std::option::Option<
                <Entity as ::doxa::policy::__private::sea_orm::EntityTrait>::Column,
            > {
                match __attr {
                    #(#attr_columns)*
                    _ => ::std::option::Option::None,
                }
            }

            #table_condition
        }

        #row

        #fetch

        #(#lookups)*
    })
}

/// The `RouteKey` impl for a composite lookup's generated key struct.
///
/// Emitted here rather than by `scoped_lookup!` because [`RouteKey`] lives
/// in `doxa-auth`, and `doxa-policy` — where that macro is defined, and
/// which spells its own paths with `$crate` so it works standalone — does
/// not depend on it. The derive already assumes the `doxa` facade, so
/// naming both halves of it costs nothing new.
///
/// Only a composite reaches this. A single-column lookup keys on the bare
/// scalar, which already has a `RouteKey` impl.
///
/// [`RouteKey`]: https://docs.rs/doxa-auth/latest/doxa_auth/granted/trait.RouteKey.html
fn route_key_impl(key: &Ident, columns: &[(Ident, Type)]) -> TokenStream {
    let kinds = columns
        .iter()
        .map(|(_, ty)| quote!(<#ty as ::doxa::auth::KeySegment>::KIND));

    // Positional, and the position is the order the columns were declared
    // in. Path segments arrive in route order and there is nothing in them
    // to match a field name against, so this is where the ordering still
    // has to be got right — which is why the struct exists for every *other*
    // call site.
    let fields = columns.iter().enumerate().map(|(index, (field, ty))| {
        quote! {
            #field: {
                let __raw = __segments.get(#index).copied().unwrap_or_default();
                <#ty as ::doxa::auth::KeySegment>::parse_segment(__raw).ok_or_else(|| {
                    ::doxa::auth::KeyError {
                        position: #index,
                        raw: ::std::borrow::ToOwned::to_owned(__raw),
                    }
                })?
            }
        }
    });

    let names = columns
        .iter()
        .map(|(field, _)| LitStr::new(&field.to_string(), field.span()));

    quote! {
        #[automatically_derived]
        impl ::doxa::auth::RouteKey for #key {
            const SEGMENTS: &'static [::doxa::policy::ResourceIdType] = &[#(#kinds),*];

            // Declared beside `SEGMENTS`, so the names and the kinds are
            // one list and cannot come to describe different segments.
            const NAMES: &'static [&'static str] = &[#(#names),*];

            fn parse(
                __segments: &[&str],
            ) -> ::std::result::Result<Self, ::doxa::auth::KeyError> {
                ::std::result::Result::Ok(Self { #(#fields),* })
            }
        }
    }
}

/// Whether SeaORM's own `#[sea_orm(primary_key)]` marks this field.
///
/// Read as tokens rather than through `parse_nested_meta`, because the
/// attribute is not ours: it carries `auto_increment`, `column_type` and
/// whatever SeaORM adds next, and a parser that has to recognise all of
/// them would fail the build over a key it was never asked about.
fn is_primary_key(field: &syn::Field) -> bool {
    field.attrs.iter().any(|attr| {
        if !attr.path().is_ident("sea_orm") {
            return false;
        }
        let syn::Meta::List(list) = &attr.meta else {
            return false;
        };
        list.tokens.clone().into_iter().any(|token| match token {
            proc_macro2::TokenTree::Ident(ident) => ident == "primary_key",
            _ => false,
        })
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
    let mut tenant_parent = None;
    let mut filters = Vec::new();

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
            } else if meta.path.is_ident("tenant_parent") {
                tenant_parent = Some(meta.value()?.parse::<LitStr>()?);
                Ok(())
            } else if meta.path.is_ident("filter") {
                // Repeatable, and `AND`ed. Two conditions written as two
                // `filter`s rather than one `.and()` chain is the same
                // query and a shorter diff when one of them changes.
                filters.push(meta.value()?.parse::<Expr>()?);
                Ok(())
            } else {
                Err(meta.error(
                    "expected `entity_type`, `id_with`, `attrs_with`, `tenant_parent` or `filter`",
                ))
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
        tenant_parent,
        filters,
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
                // Bare `key` is the unnamed lookup, one column and one per
                // struct. `key(A, B)` enrols this column in the named
                // lookups `A` and `B` — so one column can serve several
                // ways in, and several columns can compose one key.
                if meta.input.peek(syn::token::Paren) {
                    let names;
                    syn::parenthesized!(names in meta.input);
                    let names = names
                        .parse_terminated(<Ident as syn::parse::Parse>::parse, syn::Token![,])?;
                    if names.is_empty() {
                        return Err(meta.error(
                            "`key(…)` names the lookups this column takes part in, so it needs \
                             at least one; bare `key` is the unnamed one",
                        ));
                    }
                    roles.extend(names.into_iter().map(Role::NamedKey));
                } else {
                    roles.push(Role::Key);
                }
                Ok(())
            } else if meta.path.is_ident("scope") {
                roles.push(Role::Scope);
                Ok(())
            } else {
                Err(meta.error(
                    "expected `id`, `attr`, `parent = \"EntityType\"`, `key`, `key(Lookup, …)` \
                     or `scope`",
                ))
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

    /// A scope with no key is a table nothing addresses by a column — a
    /// name resolved through logic rather than matched. It still has an
    /// owner, so it still gets the listing and the attribute columns; what
    /// it does not get is a lookup, because there is no key to look up by.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn a_scope_without_a_key_is_a_table_and_not_a_lookup() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Widget")]
            struct Model {
                #[resource(id)]
                name: String,
                #[resource(attr)]
                region: String,
                #[resource(scope)]
                company_id: String,
            }
        });

        assert!(
            out.contains("impl :: doxa :: policy :: ScopedTable for Model"),
            "{out}",
        );
        assert!(out.contains("Column :: CompanyId"), "{out}");
        assert!(
            out.contains(r#""region" => :: std :: option :: Option :: Some (Column :: Region)"#),
            "a table without a key still resolves its policy attributes: {out}",
        );
        assert!(
            !out.contains("impl :: doxa :: policy :: ScopedRow for Model"),
            "no key means no lookup: {out}",
        );
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
        assert!(!out.contains("ScopedTable"), "{out}");
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
            out.contains("impl :: doxa :: policy :: ScopedTable for Model"),
            "{out}"
        );
        assert!(
            out.contains("impl :: doxa :: policy :: ScopedRow for Model"),
            "{out}"
        );
        assert!(out.contains("type Key = String"), "{out}");
        assert!(out.contains("Column :: Name"), "{out}");
        assert!(out.contains("Column :: CompanyId"), "{out}");
    }

    /// The column names go across with the lookups, because `Column::Name`
    /// is a variant and the key behind it is a bare `String` — neither can
    /// say what a route's parameter should be called. This is the field
    /// ident, which the derive is already holding.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn the_key_and_identifier_columns_are_named_for_the_route() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Connection")]
            struct Model {
                #[sea_orm(primary_key, auto_increment = false)]
                #[resource(id)]
                id: Uuid,
                #[resource(attr, key)]
                name: String,
                #[resource(scope)]
                company_id: String,
            }
        });

        assert!(
            out.contains(r#"fetch_from_scoped ! (Model , key , id = ["id"] , key = ["name"])"#),
            "{out}",
        );
    }

    /// A composite primary key is a segment each, so it is a name each —
    /// taking only the first would leave the id route a parameter short.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn a_composite_primary_key_names_every_column() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Membership")]
            struct Model {
                #[sea_orm(primary_key)]
                #[resource(id)]
                user_id: Uuid,
                #[sea_orm(primary_key)]
                group_id: Uuid,
                #[resource(scope)]
                company_id: String,
            }
        });

        assert!(
            out.contains(r#"fetch_from_scoped ! (Model , id = ["user_id" , "group_id"])"#),
            "{out}",
        );
    }

    /// A table with no `#[sea_orm(primary_key)]` in sight names none,
    /// which is the same "say nothing" every route falls back from.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn a_row_with_no_marked_primary_key_names_none() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Connection")]
            struct Model {
                #[resource(id, key)]
                name: String,
                #[resource(scope)]
                company_id: String,
            }
        });

        assert!(
            out.contains(r#"fetch_from_scoped ! (Model , key , id = [] , key = ["name"])"#),
            "{out}",
        );
    }

    /// The attributes a policy may name resolve to the columns they sit
    /// in, so a residual mentioning `resource.region` can become a `WHERE`
    /// clause. Written from the same fields as `cedar_attrs`, which is
    /// what stops a policy referring to an attribute the filter half
    /// cannot see.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn cedar_attributes_resolve_to_their_columns() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Connection")]
            struct Model {
                #[resource(id, attr, key)]
                name: String,
                #[resource(attr = "region")]
                region_code: String,
                #[resource(scope)]
                company_id: String,
            }
        });

        assert!(out.contains("fn column_for_attr"), "{out}");
        assert!(
            out.contains(r#""name" => :: std :: option :: Option :: Some (Column :: Name)"#),
            "{out}",
        );
        // The Cedar name, not the field name: a renamed attribute has to
        // resolve by what the policy calls it.
        assert!(
            out.contains(
                r#""region" => :: std :: option :: Option :: Some (Column :: RegionCode)"#
            ),
            "{out}",
        );
        // The scope column is not an attribute and gets no entry: a policy
        // naming it would be filtering on the tenant, which every lookup
        // already confines.
        assert!(!out.contains("Some (Column :: CompanyId)"), "{out}");
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

    /// The feature this exists for: one column takes part in two lookups,
    /// so a row reached both by `dataset` and by `(dataset, version)` keeps
    /// both instead of giving one up to `load_with`.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn a_column_may_take_part_in_several_named_lookups() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Version")]
            struct Model {
                #[resource(id)]
                id: Uuid,
                #[resource(key(FindByDataset, FindByPair))]
                dataset: String,
                #[resource(key(FindByPair))]
                version: i64,
                #[resource(scope)]
                tenant_id: String,
            }
        });

        // One column, two lookups, and the pair keeps both of its columns.
        // The single-column one keys on the bare scalar and so declares no
        // key struct; the composite names one.
        assert!(
            out.contains(
                "scoped_lookup ! (# [doc = \"Reaches [`Model`] by `dataset`, within the row's \
                 own scope.\"] # [automatically_derived] pub FindByDataset for Model { dataset \
                 : String => Column :: Dataset })"
            ),
            "{out}",
        );
        assert!(
            out.contains(
                "pub FindByPair as FindByPairKey for Model { dataset : String => Column :: \
                 Dataset , version : i64 => Column :: Version }"
            ),
            "{out}",
        );
    }

    /// A composite key is a struct, so it needs the `RouteKey` impl that
    /// parses it out of path segments — which a tuple got for free from the
    /// blanket impls in `doxa-auth`.
    ///
    /// It is emitted here rather than by `scoped_lookup!` because that macro
    /// lives in `doxa-policy`, which does not depend on `doxa-auth`.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn a_composite_key_gets_its_route_parsing() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Version")]
            struct Model {
                #[resource(id)]
                id: Uuid,
                #[resource(key(FindByPair))]
                dataset: String,
                #[resource(key(FindByPair))]
                version: i64,
                #[resource(scope)]
                tenant_id: String,
            }
        });

        assert!(
            out.contains("impl :: doxa :: auth :: RouteKey for FindByPairKey"),
            "{out}",
        );
        // One segment kind per column, in declaration order.
        assert!(
            out.contains(
                "SEGMENTS : & 'static [:: doxa :: policy :: ResourceIdType] = & [< String as :: \
                 doxa :: auth :: KeySegment > :: KIND , < i64 as :: doxa :: auth :: KeySegment > \
                 :: KIND]"
            ),
            "{out}",
        );
        // And a name per segment, from the same list — so the names and
        // the kinds cannot come to describe different segments.
        assert!(
            out.contains(r#"const NAMES : & 'static [& 'static str] = & ["dataset" , "version"]"#),
            "{out}",
        );
    }

    /// A single-column lookup keys on the scalar, which already has a
    /// `RouteKey` impl — so there is nothing to declare and nothing that
    /// would drag `doxa-auth` into a policy-only consumer's expansion.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn a_single_column_lookup_declares_no_key_struct() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Version")]
            struct Model {
                #[resource(id, key(FindByName))]
                name: String,
                #[resource(scope)]
                tenant_id: String,
            }
        });

        assert!(out.contains("pub FindByName for Model"), "{out}");
        assert!(!out.contains("FindByNameKey"), "{out}");
        assert!(!out.contains("doxa :: auth"), "{out}");
    }

    /// A named lookup is enough on its own: a row with no unnamed key still
    /// gets its listing and its id route, and no `ScopedRow`.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn named_lookups_need_no_unnamed_one() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Version")]
            struct Model {
                #[resource(id)]
                id: Uuid,
                #[resource(key(FindByPair))]
                dataset: String,
                #[resource(scope)]
                tenant_id: String,
            }
        });

        assert!(out.contains("pub FindByPair for Model"), "{out}");
        assert!(
            out.contains("fetch_from_scoped ! (Model , id = [])"),
            "{out}"
        );
        assert!(
            !out.contains("impl :: doxa :: policy :: ScopedRow for Model"),
            "{out}",
        );
    }

    /// Naming the same column twice in one lookup would match it against
    /// itself and add a key segment no route supplies.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn one_column_twice_in_one_lookup_is_refused() {
        let message = expand_err(quote! {
            #[resource(entity_type = "Version")]
            struct Model {
                #[resource(id, key(FindByPair, FindByPair))]
                dataset: String,
                #[resource(scope)]
                tenant_id: String,
            }
        });

        assert!(message.contains("already part of that lookup"), "{message}");
    }

    /// A named lookup is a lookup, so it needs an owner for the same reason
    /// the unnamed one does.
    #[test]
    fn a_named_lookup_without_a_scope_is_refused() {
        let message = expand_err(quote! {
            #[resource(entity_type = "Version")]
            struct Model {
                #[resource(id, key(FindByName))]
                name: String,
            }
        });

        assert!(message.contains("across every owner"), "{message}");
    }

    #[test]
    fn an_empty_key_list_is_refused() {
        let message = expand_err(quote! {
            #[resource(entity_type = "Version")]
            struct Model {
                #[resource(id, key())]
                name: String,
                #[resource(scope)]
                tenant_id: String,
            }
        });

        assert!(message.contains("at least one"), "{message}");
    }

    /// `filter` is spliced, not interpreted: whatever SeaORM accepts goes
    /// through, so there is no operator vocabulary here to fall behind.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn filters_become_one_table_condition() {
        let out = expand_ok(quote! {
            #[resource(
                entity_type = "Version",
                filter = Column::DeletedAt.is_null(),
                filter = Column::Status.eq("active"),
            )]
            struct Model {
                #[resource(id)]
                id: Uuid,
                #[resource(scope)]
                tenant_id: String,
            }
        });

        assert!(out.contains("fn table_condition ()"), "{out}");
        assert!(
            out.contains(
                "Condition :: all () . add (Column :: DeletedAt . is_null ()) . add (Column :: \
                 Status . eq (\"active\"))"
            ),
            "{out}",
        );
    }

    /// No `filter`, no override — so a table that has no such fact keeps
    /// the default and its SQL is unchanged.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn without_a_filter_there_is_no_table_condition() {
        let out = expand_ok(quote! {
            #[resource(entity_type = "Widget")]
            struct Model {
                #[resource(id, key)]
                name: String,
                #[resource(scope)]
                tenant_id: String,
            }
        });

        assert!(!out.contains("table_condition"), "{out}");
    }

    /// The condition lives on `ScopedTable`, which is what a scope column
    /// produces — so asking for one without the other has no impl to hang.
    #[test]
    fn a_filter_without_a_scope_is_refused() {
        let message = expand_err(quote! {
            #[resource(entity_type = "Widget", filter = Column::DeletedAt.is_null())]
            struct Model {
                #[resource(id)]
                name: String,
            }
        });

        assert!(message.contains("`#[resource(scope)]`"), "{message}");
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
