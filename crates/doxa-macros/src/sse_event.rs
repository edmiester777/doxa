//! Implementation of `#[derive(SseEvent)]`.
//!
//! Generates two things for a tagged event enum:
//!
//! 1. A [`SseEventMeta`][meta] impl mapping each variant to its SSE
//!    `event:` frame name (snake-case by default, overridable per variant
//!    with `#[sse(name = "…")]`).
//! 2. The enum's [`utoipa::ToSchema`] / [`utoipa::PartialSchema`] impls,
//!    emitting a **discriminated** `oneOf`: each variant becomes its own
//!    `#/components/schemas/<Enum>_<Variant>` component and the union
//!    carries an OpenAPI `discriminator`. This is the verbose, tooling-
//!    standard SSE shape utoipa's own derive can't produce for tagged
//!    enums — so callers drop `#[derive(ToSchema)]` and let `SseEvent`
//!    own it.
//!
//! Because the derive owns `ToSchema`, it requires the enum to be a serde
//! **tagged** union (`#[serde(tag = "…")]`, optionally `content = "…"`).
//! Variants may be **unit**, **newtype** (single field — emitted as a `$ref`
//! to the payload's component), or **named-struct** (fields inlined under the
//! content object; each field type must implement `utoipa::PartialSchema`, so
//! wrap `chrono`/`uuid` fields in a payload type). Multi-field tuple variants
//! are rejected.
//!
//! [meta]: ../../doxa/trait.SseEventMeta.html

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    parse2, Attribute, Data, DeriveInput, Error, Expr, ExprLit, Fields, GenericArgument, Lit,
    PathArguments, Result, Type, Variant,
};

/// Top-level entry point invoked from `lib.rs`.
pub fn expand(input: TokenStream) -> Result<TokenStream> {
    let derive_input: DeriveInput = parse2(input)?;
    let enum_name = derive_input.ident.clone();

    let data = match &derive_input.data {
        Data::Enum(data) => data,
        _ => {
            return Err(Error::new_spanned(
                &derive_input,
                "SseEvent can only be derived for enums",
            ))
        }
    };

    let serde = parse_serde_enum_attrs(&derive_input.attrs)?;
    let Some(tag) = serde.tag.as_deref() else {
        return Err(Error::new_spanned(
            &derive_input,
            "SseEvent requires a serde tag: add `#[serde(tag = \"…\")]` (optionally with `content = \"…\"`)",
        ));
    };

    let variants = data
        .variants
        .iter()
        .map(|v| parse_variant(v, serde.rename_all.as_deref()))
        .collect::<Result<Vec<_>>>()?;

    if variants.is_empty() {
        return Err(Error::new_spanned(
            &derive_input,
            "SseEvent requires at least one variant",
        ));
    }

    let meta_impl = expand_meta(&enum_name, &variants);
    let schema_impl = expand_schema(&enum_name, tag, serde.content.as_deref(), &variants);

    Ok(quote! {
        #meta_impl
        #schema_impl
    })
}

/// Generate the [`SseEventMeta`] impl (event-name metadata).
fn expand_meta(enum_name: &syn::Ident, variants: &[ParsedVariant]) -> TokenStream {
    let name_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        let name_lit = &v.event_name;
        match v.kind {
            VariantKind::Unit => quote! { Self::#ident => #name_lit, },
            VariantKind::Newtype(_) => quote! { Self::#ident(..) => #name_lit, },
            VariantKind::Struct(_) => quote! { Self::#ident { .. } => #name_lit, },
        }
    });
    let all_names = variants.iter().map(|v| v.event_name.as_str());

    quote! {
        impl ::doxa::SseEventMeta for #enum_name {
            fn event_name(&self) -> &'static str {
                match self {
                    #(#name_arms)*
                }
            }

            fn all_event_names() -> &'static [&'static str] {
                &[#(#all_names),*]
            }
        }
    }
}

/// Generate `ToSchema` + `PartialSchema` emitting the discriminated `oneOf`
/// plus a per-variant component for each event.
fn expand_schema(
    enum_name: &syn::Ident,
    tag: &str,
    content: Option<&str>,
    variants: &[ParsedVariant],
) -> TokenStream {
    let enum_name_str = enum_name.to_string();

    // Per-variant: component name, the oneOf item ($ref), the discriminator
    // mapping entry, and the component-registration statement.
    let mut oneof_items = Vec::new();
    let mut mapping_entries = Vec::new();
    let mut component_pushes = Vec::new();

    for v in variants {
        let comp_name = format!("{enum_name_str}_{}", v.ident);
        let comp_ref = format!("#/components/schemas/{comp_name}");
        let tag_value = &v.tag_value;

        oneof_items.push(quote! {
            .item(::utoipa::openapi::RefOr::Ref(
                ::utoipa::openapi::Ref::from_schema_name(#comp_name),
            ))
        });
        mapping_entries.push(quote! { (#tag_value, #comp_ref) });

        // The tag literal property: { "type": "string", "enum": ["<tag_value>"] }.
        let tag_property = quote! {
            ::utoipa::openapi::RefOr::T(::utoipa::openapi::Schema::Object(
                ::utoipa::openapi::ObjectBuilder::new()
                    .schema_type(::utoipa::openapi::schema::Type::String)
                    .enum_values(::core::option::Option::Some([#tag_value]))
                    .build(),
            ))
        };

        // The variant component schema, matching serde's wire format for the
        // tagging mode (adjacent = tag + content keys; internal = tag merged
        // into the payload via allOf).
        let component_schema = match (content, &v.kind) {
            // Adjacent tagging, newtype: { tag: <lit>, content: $ref<Payload> }.
            (Some(content), VariantKind::Newtype(payload)) => {
                let pname = payload_name_expr(payload);
                quote! {
                    ::utoipa::openapi::RefOr::T(::utoipa::openapi::Schema::Object(
                        ::utoipa::openapi::ObjectBuilder::new()
                            .schema_type(::utoipa::openapi::schema::Type::Object)
                            .property(#tag, #tag_property)
                            .property(
                                #content,
                                ::utoipa::openapi::RefOr::Ref(
                                    ::utoipa::openapi::Ref::from_schema_name(#pname),
                                ),
                            )
                            .required(#tag)
                            .required(#content)
                            .build(),
                    ))
                }
            }
            // Adjacent tagging, unit: { tag: <lit> }.
            (Some(_), VariantKind::Unit) => quote! {
                ::utoipa::openapi::RefOr::T(::utoipa::openapi::Schema::Object(
                    ::utoipa::openapi::ObjectBuilder::new()
                        .schema_type(::utoipa::openapi::schema::Type::Object)
                        .property(#tag, #tag_property)
                        .required(#tag)
                        .build(),
                ))
            },
            // Internal tagging, newtype: allOf[ $ref<Payload>, { tag: <lit> } ].
            (None, VariantKind::Newtype(payload)) => {
                let pname = payload_name_expr(payload);
                quote! {
                    ::utoipa::openapi::RefOr::T(::utoipa::openapi::Schema::AllOf(
                        ::utoipa::openapi::AllOfBuilder::new()
                            .item(::utoipa::openapi::RefOr::Ref(
                                ::utoipa::openapi::Ref::from_schema_name(#pname),
                            ))
                            .item(::utoipa::openapi::RefOr::T(::utoipa::openapi::Schema::Object(
                                ::utoipa::openapi::ObjectBuilder::new()
                                    .schema_type(::utoipa::openapi::schema::Type::Object)
                                    .property(#tag, #tag_property)
                                    .required(#tag)
                                    .build(),
                            )))
                            .build(),
                    ))
                }
            }
            // Internal tagging, unit: { tag: <lit> }.
            (None, VariantKind::Unit) => quote! {
                ::utoipa::openapi::RefOr::T(::utoipa::openapi::Schema::Object(
                    ::utoipa::openapi::ObjectBuilder::new()
                        .schema_type(::utoipa::openapi::schema::Type::Object)
                        .property(#tag, #tag_property)
                        .required(#tag)
                        .build(),
                ))
            },
            // Adjacent tagging, struct: { tag: <lit>, content: { …fields… } }.
            // The content object's fields are inlined from their own
            // `PartialSchema`; their transitive component deps are registered
            // below so no `$ref` dangles.
            (Some(content), VariantKind::Struct(fields)) => {
                let props = struct_field_props(fields);
                quote! {
                    ::utoipa::openapi::RefOr::T(::utoipa::openapi::Schema::Object(
                        ::utoipa::openapi::ObjectBuilder::new()
                            .schema_type(::utoipa::openapi::schema::Type::Object)
                            .property(#tag, #tag_property)
                            .property(
                                #content,
                                ::utoipa::openapi::RefOr::T(::utoipa::openapi::Schema::Object(
                                    ::utoipa::openapi::ObjectBuilder::new()
                                        .schema_type(::utoipa::openapi::schema::Type::Object)
                                        #(#props)*
                                        .build(),
                                )),
                            )
                            .required(#tag)
                            .required(#content)
                            .build(),
                    ))
                }
            }
            // Internal tagging, struct: fields merged alongside the tag.
            (None, VariantKind::Struct(fields)) => {
                let props = struct_field_props(fields);
                quote! {
                    ::utoipa::openapi::RefOr::T(::utoipa::openapi::Schema::Object(
                        ::utoipa::openapi::ObjectBuilder::new()
                            .schema_type(::utoipa::openapi::schema::Type::Object)
                            .property(#tag, #tag_property)
                            #(#props)*
                            .required(#tag)
                            .build(),
                    ))
                }
            }
        };

        component_pushes.push(quote! {
            schemas.push((#comp_name.to_string(), #component_schema));
        });

        // Register the payload component and every nested generic argument.
        // `<Payload>::name()` collapses generics to the base ident
        // (`Envelope<RunStarted>` -> "Envelope"), and utoipa's generic
        // `schemas()` registers a type's deps but not its own generic
        // arguments — so both the monomorphized payload names and the argument
        // components are emitted here to keep every `$ref` resolvable.
        if let VariantKind::Newtype(payload) = &v.kind {
            component_pushes.extend(emit_registration(payload, payload_name_expr(payload)));
        }

        // Struct variants inline their fields; register each field type's
        // transitive component deps so the inlined `$ref`s resolve.
        if let VariantKind::Struct(fields) = &v.kind {
            for f in fields {
                let ty = &f.ty;
                component_pushes.push(quote! {
                    <#ty as ::utoipa::ToSchema>::schemas(schemas);
                });
            }
        }
    }

    quote! {
        impl ::utoipa::PartialSchema for #enum_name {
            fn schema() -> ::utoipa::openapi::RefOr<::utoipa::openapi::schema::Schema> {
                ::utoipa::openapi::RefOr::T(::utoipa::openapi::Schema::OneOf(
                    ::utoipa::openapi::OneOfBuilder::new()
                        #(#oneof_items)*
                        .discriminator(::core::option::Option::Some(
                            ::utoipa::openapi::Discriminator::with_mapping(#tag, [#(#mapping_entries),*]),
                        ))
                        .build(),
                ))
            }
        }

        impl ::utoipa::ToSchema for #enum_name {
            fn name() -> ::std::borrow::Cow<'static, str> {
                ::std::borrow::Cow::Borrowed(#enum_name_str)
            }

            fn schemas(
                schemas: &mut ::std::vec::Vec<(
                    ::std::string::String,
                    ::utoipa::openapi::RefOr<::utoipa::openapi::schema::Schema>,
                )>,
            ) {
                #(#component_pushes)*
            }
        }
    }
}

/// Enum-level serde attributes relevant to the schema shape.
#[derive(Default)]
struct SerdeEnumAttrs {
    tag: Option<String>,
    content: Option<String>,
    rename_all: Option<String>,
}

/// Parsed metadata for one variant.
struct ParsedVariant {
    ident: syn::Ident,
    /// SSE `event:` frame name (`#[sse(name)]` or snake-case of the ident).
    event_name: String,
    /// serde tag value (the JSON discriminator value): `#[serde(rename)]`
    /// or `rename_all` applied to the ident. Distinct from `event_name`.
    tag_value: String,
    kind: VariantKind,
}

enum VariantKind {
    Unit,
    Newtype(Type),
    Struct(Vec<StructField>),
}

/// A named field of a struct variant. SSE event enums don't rename fields,
/// so the JSON key is the field ident verbatim.
struct StructField {
    name: String,
    ty: Type,
    /// `Option<…>` fields are omitted from `required`.
    optional: bool,
}

fn parse_variant(variant: &Variant, rename_all: Option<&str>) -> Result<ParsedVariant> {
    let ident_str = variant.ident.to_string();

    let event_name = parse_sse_name_attr(&variant.attrs)?
        .unwrap_or_else(|| apply_rename(&ident_str, Some("snake_case")));

    let tag_value = parse_serde_rename_attr(&variant.attrs)?
        .unwrap_or_else(|| apply_rename(&ident_str, rename_all));

    let kind = match &variant.fields {
        Fields::Unit => VariantKind::Unit,
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            VariantKind::Newtype(fields.unnamed[0].ty.clone())
        }
        Fields::Named(fields) => VariantKind::Struct(
            fields
                .named
                .iter()
                .map(|f| StructField {
                    name: f
                        .ident
                        .as_ref()
                        .expect("named field has an ident")
                        .to_string(),
                    ty: f.ty.clone(),
                    optional: is_option(&f.ty),
                })
                .collect(),
        ),
        Fields::Unnamed(_) => {
            return Err(Error::new_spanned(
                variant,
                "SseEvent does not support multi-field tuple variants — use a unit, a \
                 single-field (newtype) variant, or named struct fields",
            ))
        }
    };

    Ok(ParsedVariant {
        ident: variant.ident.clone(),
        event_name,
        tag_value,
        kind,
    })
}

/// Parse `#[sse(name = "…")]` from a variant's attribute list.
fn parse_sse_name_attr(attrs: &[Attribute]) -> Result<Option<String>> {
    let mut found: Option<String> = None;
    for attr in attrs {
        if !attr.path().is_ident("sse") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("name") {
                found = Some(parse_string_value(&meta)?);
                Ok(())
            } else {
                Err(meta.error("unknown key in #[sse(...)]; expected `name`"))
            }
        })?;
    }
    Ok(found)
}

/// Parse `#[serde(rename = "…")]` from a variant's attribute list, ignoring
/// every other serde key.
fn parse_serde_rename_attr(attrs: &[Attribute]) -> Result<Option<String>> {
    let mut found: Option<String> = None;
    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename") {
                // serde `rename` can be a string or `serialize`/`deserialize`
                // map; SSE enums use the simple string form.
                if let Ok(value) = parse_string_value(&meta) {
                    found = Some(value);
                }
                Ok(())
            } else {
                skip_meta_value(&meta)
            }
        })?;
    }
    Ok(found)
}

/// Parse the enum-level `#[serde(tag, content, rename_all)]` attributes.
fn parse_serde_enum_attrs(attrs: &[Attribute]) -> Result<SerdeEnumAttrs> {
    let mut out = SerdeEnumAttrs::default();
    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("tag") {
                out.tag = Some(parse_string_value(&meta)?);
            } else if meta.path.is_ident("content") {
                out.content = Some(parse_string_value(&meta)?);
            } else if meta.path.is_ident("rename_all") {
                out.rename_all = Some(parse_string_value(&meta)?);
            } else {
                return skip_meta_value(&meta);
            }
            Ok(())
        })?;
    }
    Ok(out)
}

/// Read a `key = "string"` value from a nested-meta callback.
fn parse_string_value(meta: &syn::meta::ParseNestedMeta) -> Result<String> {
    let value = meta.value()?;
    let expr: Expr = value.parse()?;
    if let Expr::Lit(ExprLit {
        lit: Lit::Str(s), ..
    }) = expr
    {
        Ok(s.value())
    } else {
        Err(meta.error("expected a string literal"))
    }
}

/// Consume and discard the value of an unrecognized nested meta so parsing
/// of the remaining serde keys can continue.
fn skip_meta_value(meta: &syn::meta::ParseNestedMeta) -> Result<()> {
    if meta.input.peek(syn::Token![=]) {
        let _: Expr = meta.value()?.parse()?;
    } else if meta.input.peek(syn::token::Paren) {
        let _: proc_macro2::Group = meta.input.parse()?;
    }
    Ok(())
}

/// Apply a serde `rename_all` rule to a PascalCase variant ident. Covers the
/// rules serde supports; an unrecognized rule falls back to the ident
/// unchanged (matching serde's "no rename" behavior for `None`).
fn apply_rename(variant: &str, rule: Option<&str>) -> String {
    match rule {
        None | Some("PascalCase") => variant.to_owned(),
        Some("lowercase") => variant.to_lowercase(),
        Some("UPPERCASE") => variant.to_uppercase(),
        Some("camelCase") => {
            let mut chars = variant.chars();
            match chars.next() {
                Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        }
        Some("snake_case") => split_words(variant).join("_"),
        Some("kebab-case") => split_words(variant).join("-"),
        Some("SCREAMING_SNAKE_CASE") => split_words(variant).join("_").to_uppercase(),
        Some("SCREAMING-KEBAB-CASE") => split_words(variant).join("-").to_uppercase(),
        Some(_) => variant.to_owned(),
    }
}

/// Split a PascalCase identifier into lowercase words at each uppercase
/// boundary, matching serde's char-based snake_case rule (acronym runs like
/// `HTTPError` become `h_t_t_p_error`).
fn split_words(s: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            words.push(c.to_ascii_lowercase().to_string());
        } else if let Some(last) = words.last_mut() {
            last.push(c);
        } else {
            words.push(c.to_string());
        }
    }
    words
}

/// Build the `.property(name, schema).required(name)` tokens for each field
/// of a struct variant. Field schemas are inlined from each field type's
/// `PartialSchema`; `Option<…>` fields are omitted from `required`.
fn struct_field_props(fields: &[StructField]) -> Vec<TokenStream> {
    fields
        .iter()
        .map(|f| {
            let name = &f.name;
            let ty = &f.ty;
            let required = if f.optional {
                quote! {}
            } else {
                quote! { .required(#name) }
            };
            quote! {
                .property(#name, <#ty as ::utoipa::PartialSchema>::schema())
                #required
            }
        })
        .collect()
}

/// Whether a field type is `Option<…>` (by last path segment, so both
/// `Option<T>` and `std::option::Option<T>` count).
fn is_option(ty: &Type) -> bool {
    matches!(ty, Type::Path(tp) if tp.path.segments.last().is_some_and(|s| s.ident == "Option"))
}

/// The schema name used to reference a newtype variant's payload component.
///
/// Defers to `<Payload as ToSchema>::name()` for a concrete payload so
/// `#[schema(rename)]` is honored. For a *generic* payload utoipa erases the
/// type arguments in `name()` (`Envelope<RunStarted>` → `"Envelope"`), which
/// would collapse every variant onto one component — so the name is composed
/// from the monomorphization to match utoipa's own generic naming
/// (`Envelope_RunStarted`, `Envelope_FormRequested_RequestedForm`).
fn payload_name_expr(ty: &Type) -> TokenStream {
    match composed_generic_name(ty) {
        Some(name) => quote! { #name },
        None => quote! { <#ty as ::utoipa::ToSchema>::name() },
    }
}

/// Emit registration statements for a newtype payload and every nested generic
/// argument. The payload is registered under `name_expr` (its monomorphized
/// name for generics); each generic argument is registered under
/// `<Arg as ToSchema>::name()` — the same name utoipa emits for the `$ref`
/// inside the parent's own schema — and recursed into, so no inner `$ref`
/// dangles regardless of nesting depth.
fn emit_registration(ty: &Type, name_expr: TokenStream) -> Vec<TokenStream> {
    let args = generic_args(ty);

    // utoipa emits the inner `$ref` for a generic argument under its base ident
    // (`Wrap<A>` -> `$ref Wrap`), so sibling monomorphizations collapse onto one
    // component. Rewrite each such ref to the argument's composed name to keep
    // them distinct.
    let rewrites = args.iter().filter_map(|arg| {
        let composed = composed_generic_name(arg)?;
        Some(quote! {
            ::doxa::__private::rewrite_schema_refs(
                &mut __schema,
                <#arg as ::utoipa::ToSchema>::name().as_ref(),
                #composed,
            );
        })
    });

    let mut out = vec![quote! {
        {
            let __name = ::std::string::String::from(#name_expr);
            if !schemas.iter().any(|(__n, _)| *__n == __name) {
                let mut __schema = <#ty as ::utoipa::PartialSchema>::schema();
                #(#rewrites)*
                schemas.push((__name, __schema));
            }
            <#ty as ::utoipa::ToSchema>::schemas(schemas);
        }
    }];

    // Recurse under the *composed* name so the argument component matches the
    // rewritten ref above.
    for arg in &args {
        out.extend(emit_registration(arg, payload_name_expr(arg)));
    }
    out
}

/// The angle-bracketed generic type arguments of a path type (empty otherwise).
fn generic_args(ty: &Type) -> Vec<Type> {
    let Type::Path(tp) = ty else {
        return Vec::new();
    };
    let Some(seg) = tp.path.segments.last() else {
        return Vec::new();
    };
    let PathArguments::AngleBracketed(args) = &seg.arguments else {
        return Vec::new();
    };
    args.args
        .iter()
        .filter_map(|a| match a {
            GenericArgument::Type(t) => Some(t.clone()),
            _ => None,
        })
        .collect()
}

/// `Some(composed)` when `ty` carries angle-bracketed type arguments; `None`
/// for a non-generic path (the caller falls back to `ToSchema::name()`).
fn composed_generic_name(ty: &Type) -> Option<String> {
    let Type::Path(tp) = ty else { return None };
    let seg = tp.path.segments.last()?;
    if !matches!(seg.arguments, PathArguments::AngleBracketed(_)) {
        return None;
    }
    Some(monomorphized_name(ty))
}

/// Joins a type's path-final ident with each generic type argument's name,
/// recursively and underscore-separated — matching utoipa's generic schema
/// naming so the composed `$ref` resolves to the registered component.
fn monomorphized_name(ty: &Type) -> String {
    let Type::Path(tp) = ty else {
        return "Schema".to_string();
    };
    let Some(seg) = tp.path.segments.last() else {
        return "Schema".to_string();
    };
    let mut name = seg.ident.to_string();
    if let PathArguments::AngleBracketed(args) = &seg.arguments {
        for arg in &args.args {
            if let GenericArgument::Type(inner) = arg {
                name.push('_');
                name.push_str(&monomorphized_name(inner));
            }
        }
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snake_case_rename_matches_serde() {
        assert_eq!(apply_rename("Started", Some("snake_case")), "started");
        assert_eq!(
            apply_rename("InProgress", Some("snake_case")),
            "in_progress"
        );
        assert_eq!(
            apply_rename("RunStarted", Some("snake_case")),
            "run_started"
        );
    }

    #[test]
    fn other_rename_rules() {
        assert_eq!(apply_rename("RunStarted", None), "RunStarted");
        assert_eq!(apply_rename("RunStarted", Some("camelCase")), "runStarted");
        assert_eq!(
            apply_rename("RunStarted", Some("kebab-case")),
            "run-started"
        );
        assert_eq!(
            apply_rename("RunStarted", Some("SCREAMING_SNAKE_CASE")),
            "RUN_STARTED"
        );
    }
}
