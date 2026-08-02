//! `#[derive(PolicyResource)]` — Cedar entity identity for a domain type.
//!
//! One declaration produces the Cedar entity type, the instance id, the
//! attributes policies may reference, and the parent list. The entity
//! type doubles as the audit `resource_type`, so an audit row and the
//! decision that produced it share one string.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Ident, LitStr, Result, Type};

/// Role a field plays in the generated impl.
enum Role {
    Id,
    Attr(String),
    Parent(LitStr),
}

pub fn expand(input: TokenStream) -> Result<TokenStream> {
    let input: DeriveInput = syn::parse2(input)?;
    let ident = &input.ident;

    let (entity_type, id_type_override) = container_args(&input)?;

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

    let mut id_field: Option<(Ident, Type)> = None;
    let mut attrs: Vec<(String, Ident)> = Vec::new();
    let mut parents: Vec<(LitStr, Ident)> = Vec::new();

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
                    id_field = Some((name.clone(), field.ty.clone()));
                }
                Role::Attr(key) => attrs.push((key, name.clone())),
                Role::Parent(ty) => parents.push((ty, name.clone())),
            }
        }
    }

    let (id_ident, id_ty) = id_field.ok_or_else(|| {
        syn::Error::new_spanned(
            &input.ident,
            "`PolicyResource` needs one field marked `#[resource(id)]`",
        )
    })?;

    let id_type_variant = match id_type_override {
        Some(lit) => id_type_from_str(&lit)?,
        None => infer_id_type(&id_ty),
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

    let parent_pushes = parents.iter().map(|(entity, field)| {
        quote! { __parents.push((#entity, ::std::string::ToString::to_string(&self.#field))); }
    });

    Ok(quote! {
        #[automatically_derived]
        impl ::doxa::policy::PolicyResource for #ident {
            const ENTITY_TYPE: &'static str = #entity_type;
            const ID_TYPE: ::doxa::policy::ResourceIdType = #id_type_variant;

            type Id = #id_ty;

            fn resource_id(&self) -> ::std::string::String {
                ::std::string::ToString::to_string(&self.#id_ident)
            }

            fn cedar_attrs(
                &self,
            ) -> ::doxa::__private::serde_json::Map<
                ::std::string::String,
                ::doxa::__private::serde_json::Value,
            > {
                let mut __map = ::doxa::__private::serde_json::Map::new();
                #(#attr_inserts)*
                __map
            }

            fn cedar_parents(&self) -> ::std::vec::Vec<(&'static str, ::std::string::String)> {
                let mut __parents = ::std::vec::Vec::new();
                #(#parent_pushes)*
                __parents
            }
        }
    })
}

/// Parse `#[resource(entity_type = "…", id_type = "…")]` off the struct.
fn container_args(input: &DeriveInput) -> Result<(LitStr, Option<LitStr>)> {
    let mut entity_type = None;
    let mut id_type = None;

    for attr in &input.attrs {
        if !attr.path().is_ident("resource") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("entity_type") {
                entity_type = Some(meta.value()?.parse::<LitStr>()?);
                Ok(())
            } else if meta.path.is_ident("id_type") {
                id_type = Some(meta.value()?.parse::<LitStr>()?);
                Ok(())
            } else {
                Err(meta.error("expected `entity_type` or `id_type`"))
            }
        })?;
    }

    let entity_type = entity_type.ok_or_else(|| {
        syn::Error::new_spanned(
            &input.ident,
            "missing `#[resource(entity_type = \"…\")]` on the struct",
        )
    })?;
    Ok((entity_type, id_type))
}

/// Parse `#[resource(id)]` / `#[resource(attr)]` / `#[resource(attr =
/// "key")]` / `#[resource(parent = "Folder")]` off one field.
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
            } else {
                Err(meta.error("expected `id`, `attr`, or `parent = \"EntityType\"`"))
            }
        })?;
    }

    Ok(roles)
}

fn id_type_from_str(lit: &LitStr) -> Result<TokenStream> {
    match lit.value().as_str() {
        "string" => Ok(quote! { ::doxa::policy::ResourceIdType::String }),
        "integer" => Ok(quote! { ::doxa::policy::ResourceIdType::Integer }),
        "uuid" => Ok(quote! { ::doxa::policy::ResourceIdType::Uuid }),
        other => Err(syn::Error::new(
            lit.span(),
            format!("unknown `id_type` `{other}` — expected `string`, `integer`, or `uuid`"),
        )),
    }
}

/// Guess the OpenAPI primitive from the id field's type. Anything
/// unrecognized documents as a string, which is always wire-accurate.
fn infer_id_type(ty: &Type) -> TokenStream {
    let Type::Path(type_path) = ty else {
        return quote! { ::doxa::policy::ResourceIdType::String };
    };
    let Some(last) = type_path.path.segments.last() else {
        return quote! { ::doxa::policy::ResourceIdType::String };
    };

    match last.ident.to_string().as_str() {
        "u8" | "u16" | "u32" | "u64" | "usize" | "i8" | "i16" | "i32" | "i64" | "isize" => {
            quote! { ::doxa::policy::ResourceIdType::Integer }
        }
        "Uuid" => quote! { ::doxa::policy::ResourceIdType::Uuid },
        _ => quote! { ::doxa::policy::ResourceIdType::String },
    }
}
