//! Rust types for the schemas a client's routes reach, with their serde shape and the
//! constraints the client checks before sending.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote};

use super::spec::{Additional, IdentityMeta, Scalar, Schema, Spec};
use super::{GenerateError, TypeMap};

/// Where a schema is being read, for naming inline types and for errors.
pub(crate) struct At<'a> {
    pub operation: &'a str,
    pub hint: String,
}

impl At<'_> {
    fn unsupported(&self, schema: &str, reason: impl Into<String>) -> GenerateError {
        GenerateError::Unsupported {
            schema: schema.to_owned(),
            operation: self.operation.to_owned(),
            reason: reason.into(),
        }
    }

    fn child(&self, hint: String) -> At<'_> {
        At {
            operation: self.operation,
            hint,
        }
    }
}

/// A type the client defines, from a component or an inline schema.
struct Pending {
    name: String,
    schema: Schema,
    operation: String,
}

pub(crate) struct Types<'a> {
    spec: &'a Spec,
    map: &'a TypeMap,
    queue: Vec<Pending>,
    named: BTreeSet<String>,
    identities: BTreeMap<String, IdentityMeta>,
    mapped: BTreeSet<String>,
}

impl<'a> Types<'a> {
    pub fn new(spec: &'a Spec, map: &'a TypeMap) -> Result<Self, GenerateError> {
        for path in map.formats.values().chain(map.schemas.values()) {
            parse_path(path)?;
        }
        Ok(Types {
            spec,
            map,
            queue: Vec::new(),
            named: BTreeSet::new(),
            identities: BTreeMap::new(),
            mapped: map
                .formats
                .values()
                .chain(map.schemas.values())
                .cloned()
                .collect(),
        })
    }

    /// Mark the component `schema` as an entity the client cache stores by identity.
    pub fn identity(&mut self, meta: &IdentityMeta) {
        self.identities.insert(meta.schema.clone(), meta.clone());
    }

    /// The type a component, named by the server, becomes.
    pub fn component(&mut self, name: &str, at: &At<'_>) -> Result<TokenStream, GenerateError> {
        let schema = Schema {
            reference: Some(format!("#/components/schemas/{name}")),
            ..Schema::default()
        };
        self.ty(&schema, at)
    }

    /// The Rust type for `schema`, defining every type it reaches.
    pub fn ty(&mut self, schema: &Schema, at: &At<'_>) -> Result<TokenStream, GenerateError> {
        if let Some(name) = schema.ref_name() {
            if let Some(path) = self.map.schemas.get(name) {
                return parse_path(path);
            }
            let component = self
                .spec
                .components
                .schemas
                .get(name)
                .ok_or_else(|| at.unsupported(name, "isn't in the document's components"))?;
            if !nameable(component) {
                return self.ty(component, &at.child(pascal(name)));
            }
            return Ok(self.define(name, component, at));
        }
        if let [only] = schema.all_of.as_slice() {
            return self.ty(only, at);
        }
        if let Some(inner) = or_null(schema) {
            let inner = self.ty(inner, at)?;
            return Ok(quote!(::core::option::Option<#inner>));
        }
        let (ty, nullable) = match &schema.ty {
            Some(t) => t.split(),
            None => (None, false),
        };
        let inner = match ty {
            Some("string") if !schema.values.is_empty() => self.inline(schema, at),
            Some("string") => match schema.format.as_deref() {
                Some("binary") => quote!(::std::vec::Vec<u8>),
                Some(f) if self.map.formats.contains_key(f) => parse_path(&self.map.formats[f])?,
                _ => quote!(::std::string::String),
            },
            Some("integer") => integer(schema),
            Some("number") if schema.format.as_deref() == Some("float") => quote!(f32),
            Some("number") => quote!(f64),
            Some("boolean") => quote!(bool),
            Some("array") => {
                let items = match &schema.items {
                    Some(items) => self.ty(items, &at.child(format!("{}Item", at.hint)))?,
                    None => quote!(::doxa::wire::__Value),
                };
                quote!(::std::vec::Vec<#items>)
            }
            Some("object") | None if !schema.properties.is_empty() || !schema.one_of.is_empty() => {
                match self.component_like(schema) {
                    Some(name) => {
                        let component = self.spec.components.schemas[&name].clone();
                        self.define(&name, &component, at)
                    }
                    None => self.inline(schema, at),
                }
            }
            Some("object") | None => match &schema.additional_properties {
                Some(Additional::Schema(values)) => {
                    let v = self.ty(values, &at.child(format!("{}Value", at.hint)))?;
                    quote!(::std::collections::BTreeMap<::std::string::String, #v>)
                }
                _ if ty.is_none() && nullable => quote!(()),
                _ => quote!(::doxa::wire::__Value),
            },
            Some(other) => return Err(at.unsupported(&at.hint, format!("has type `{other}`"))),
        };
        Ok(if nullable {
            quote!(::core::option::Option<#inner>)
        } else {
            inner
        })
    }

    /// A component the inline `schema` is a copy of, as utoipa writes `Vec<T>`'s items.
    fn component_like(&self, schema: &Schema) -> Option<String> {
        self.spec
            .components
            .schemas
            .iter()
            .find(|(_, c)| *c == schema)
            .map(|(n, _)| n.clone())
    }

    fn define(&mut self, name: &str, schema: &Schema, at: &At<'_>) -> TokenStream {
        let ident = Ident::new(&pascal(name), Span::call_site());
        if self.named.insert(pascal(name)) {
            self.queue.push(Pending {
                name: name.to_owned(),
                schema: schema.clone(),
                operation: at.operation.to_owned(),
            });
        }
        quote!(#ident)
    }

    fn inline(&mut self, schema: &Schema, at: &At<'_>) -> TokenStream {
        let mut name = at.hint.clone();
        let mut n = 2;
        while self.named.contains(&name) {
            name = format!("{}{n}", at.hint);
            n += 1;
        }
        self.define(&name, schema, at)
    }

    /// A struct of query parameters, named `name`.
    pub fn query(
        &mut self,
        name: &str,
        params: Vec<(String, Schema, bool)>,
        at: &At<'_>,
    ) -> TokenStream {
        let schema = Schema {
            ty: Some(super::spec::Types::One("object".into())),
            required: params
                .iter()
                .filter(|(_, _, req)| *req)
                .map(|(n, _, _)| n.clone())
                .collect(),
            properties: params
                .into_iter()
                .map(|(n, s, _)| (n, non_null(s)))
                .collect(),
            ..Schema::default()
        };
        self.define(name, &schema, at)
    }

    /// Every type defined so far, and the ones they reach.
    pub fn render(&mut self) -> Result<TokenStream, GenerateError> {
        let mut out = TokenStream::new();
        while let Some(p) = self.queue.pop() {
            let at = At {
                operation: &p.operation,
                hint: pascal(&p.name),
            };
            out.extend(self.render_one(&p.name, &p.schema, &at)?);
        }
        let mapped = self
            .mapped
            .iter()
            .map(|p| parse_path(p))
            .collect::<Result<Vec<_>, _>>()?;
        let prelude = prelude(&mapped);
        Ok(quote!(#prelude #out))
    }

    fn render_one(
        &mut self,
        name: &str,
        schema: &Schema,
        at: &At<'_>,
    ) -> Result<TokenStream, GenerateError> {
        let ident = Ident::new(&pascal(name), Span::call_site());
        let docs = doc(schema.description.as_deref());
        if !schema.values.is_empty() {
            return string_enum(&ident, &docs, schema, name, at);
        }
        if !schema.one_of.is_empty() {
            return match &schema.discriminator {
                Some(d) => self.tagged(&ident, &docs, schema, &d.property_name, at),
                None => self.external(&ident, &docs, schema, name, at),
            };
        }
        let fields = self.fields(schema, at)?;
        let default = fields
            .iter()
            .all(|f| f.optional)
            .then(|| quote!(#[derive(::core::default::Default)]));
        let checks = fields.iter().map(|f| f.check.clone());
        let decls = fields.iter().map(|f| f.decl.clone());
        let identity = match self.identities.get(name) {
            Some(meta) => {
                let entity = &meta.entity;
                let id = field_ident(&meta.id).0;
                let key = meta.key.as_ref().map(|k| {
                    let ty = format_ident!("{}", k.ty);
                    let fields = k.fields.iter().map(|f| field_ident(f).0);
                    quote!(, key = #ty { #(#fields),* })
                });
                quote! {
                    #[derive(::doxa::Identity)]
                    #[identity(entity = #entity, id = #id #key)]
                }
            }
            None => quote!(),
        };
        Ok(quote! {
            #docs
            #DERIVES
            #default
            #identity
            pub struct #ident { #(#decls,)* }

            impl __Constraints for #ident {
                fn check_into(&self, path: &str, out: &mut ::doxa::wire::FieldErrors) {
                    let _ = (&path, &out);
                    #(#checks)*
                }
            }
        })
    }

    /// Whether [`Types::ty`] wraps `schema`'s type in `Option` because it allows `null`.
    fn nullable(&self, schema: &Schema) -> bool {
        if let Some(name) = schema.ref_name() {
            return !self.map.schemas.contains_key(name)
                && self
                    .spec
                    .components
                    .schemas
                    .get(name)
                    .is_some_and(|c| !nameable(c) && self.nullable(c));
        }
        if let [only] = schema.all_of.as_slice() {
            return self.nullable(only);
        }
        or_null(schema).is_some() || schema.ty.as_ref().is_some_and(|t| t.split().1)
    }

    /// Each property by `required` and `nullable`; absent and nullable is `Option<Option<T>>`.
    fn fields(&mut self, schema: &Schema, at: &At<'_>) -> Result<Vec<Field>, GenerateError> {
        let mut out = Vec::new();
        for (name, prop) in &schema.properties {
            let required = schema.required.contains(name);
            let nullable = self.nullable(prop);
            let ty = self.ty(prop, &at.child(format!("{}{}", at.hint, pascal(name))))?;
            let (ident, renamed) = field_ident(name);
            let rename = renamed.then(|| quote!(#[serde(rename = #name)]));
            let docs = doc(prop.description.as_deref());
            let (ty, default) = match (required, nullable) {
                (true, _) => (ty, quote!()),
                (false, false) => (
                    quote!(::core::option::Option<#ty>),
                    quote!(#[serde(default, skip_serializing_if = "Option::is_none")]),
                ),
                (false, true) => (
                    quote!(::core::option::Option<#ty>),
                    quote!(#[serde(
                        default,
                        skip_serializing_if = "Option::is_none",
                        with = "::doxa::wire::double_option"
                    )]),
                ),
            };
            let layers = usize::from(!required) + usize::from(nullable);
            let some = quote!(::core::option::Option::Some);
            let rules = constraints(prop, name);
            let body = quote! {
                let at = __join(path, #name);
                #rules
                __Constraints::check_into(v, &at, out);
            };
            let check = match layers {
                0 => quote!({ let v = &self.#ident; #body }),
                1 => quote!(if let #some(v) = &self.#ident { #body }),
                _ => quote!(if let #some(#some(v)) = &self.#ident { #body }),
            };
            out.push(Field {
                optional: layers > 0,
                decl: quote!(#docs #rename #default pub #ident: #ty),
                bare: quote!(#docs #rename #default #ident: #ty),
                check,
            });
        }
        Ok(out)
    }

    /// `oneOf` with a discriminator: the tag, and the rest inline or under one content key.
    fn tagged(
        &mut self,
        ident: &Ident,
        docs: &TokenStream,
        schema: &Schema,
        tag: &str,
        at: &At<'_>,
    ) -> Result<TokenStream, GenerateError> {
        let branches: Vec<(Option<String>, Schema)> = schema
            .one_of
            .iter()
            .map(|b| match b.ref_name() {
                Some(n) => self
                    .spec
                    .components
                    .schemas
                    .get(n)
                    .cloned()
                    .map(|s| (Some(n.to_owned()), s))
                    .ok_or_else(|| at.unsupported(n, "isn't in the document's components")),
                None => Ok((None, b.clone())),
            })
            .collect::<Result<_, _>>()?;
        let others: BTreeSet<&String> = branches
            .iter()
            .flat_map(|(_, b)| b.properties.keys().filter(|k| *k != tag))
            .collect();
        let content = match others.iter().collect::<Vec<_>>().as_slice() {
            [only] => Some((**only).clone()),
            _ => None,
        };
        let mut variants = Vec::new();
        for (name, branch) in &branches {
            let value = branch
                .properties
                .get(tag)
                .and_then(|t| t.values.first())
                .and_then(|v| match v {
                    Scalar::Str(s) => Some(s.clone()),
                    _ => None,
                })
                .ok_or_else(|| {
                    at.unsupported(
                        name.as_deref().unwrap_or(&at.hint),
                        format!("is a `oneOf` branch whose `{tag}` isn't a string constant"),
                    )
                })?;
            let variant = Ident::new(&pascal(&value), Span::call_site());
            let hint = format!("{}{}", at.hint, pascal(&value));
            let body = match &content {
                Some(key) => match branch.properties.get(key) {
                    None => quote!(),
                    Some(c) if c.ref_name().is_none() && !c.properties.is_empty() => {
                        let fields = self.fields(c, &at.child(hint))?;
                        let decls = fields.iter().map(|f| &f.bare);
                        quote!({ #(#decls,)* })
                    }
                    Some(c) => {
                        let ty = self.ty(c, &at.child(hint))?;
                        quote!((#ty))
                    }
                },
                None => {
                    let mut rest = branch.clone();
                    rest.properties.remove(tag);
                    rest.required.retain(|r| r != tag);
                    if rest.properties.is_empty() {
                        quote!()
                    } else {
                        let fields = self.fields(&rest, &at.child(hint))?;
                        let decls = fields.iter().map(|f| &f.bare);
                        quote!({ #(#decls,)* })
                    }
                }
            };
            variants.push(quote!(#[serde(rename = #value)] #variant #body));
        }
        let repr = match &content {
            Some(c) => quote!(#[serde(tag = #tag, content = #c)]),
            None => quote!(#[serde(tag = #tag)]),
        };
        Ok(enum_items(ident, docs, repr, &variants))
    }

    /// `oneOf` without one, as serde writes an externally tagged enum.
    fn external(
        &mut self,
        ident: &Ident,
        docs: &TokenStream,
        schema: &Schema,
        name: &str,
        at: &At<'_>,
    ) -> Result<TokenStream, GenerateError> {
        let mut variants = Vec::new();
        for branch in &schema.one_of {
            let branch = match branch.ref_name() {
                Some(n) => self
                    .spec
                    .components
                    .schemas
                    .get(n)
                    .cloned()
                    .unwrap_or_default(),
                None => branch.clone(),
            };
            if !branch.values.is_empty() {
                for v in &branch.values {
                    let Scalar::Str(v) = v else {
                        return Err(at.unsupported(name, "has a non-string enum value"));
                    };
                    let variant = Ident::new(&pascal(v), Span::call_site());
                    variants.push(quote!(#[serde(rename = #v)] #variant));
                }
                continue;
            }
            let [(key, payload)] = branch.properties.iter().collect::<Vec<_>>()[..] else {
                return Err(at.unsupported(
                    name,
                    "is a `oneOf` that is neither tagged nor one key per branch",
                ));
            };
            let variant = Ident::new(&pascal(key), Span::call_site());
            let ty = self.ty(payload, &at.child(format!("{}{}", at.hint, pascal(key))))?;
            variants.push(quote!(#[serde(rename = #key)] #variant(#ty)));
        }
        Ok(enum_items(ident, docs, quote!(), &variants))
    }
}

struct Field {
    optional: bool,
    decl: TokenStream,
    /// Without `pub`, for an enum variant.
    bare: TokenStream,
    check: TokenStream,
}

const DERIVES: Derives = Derives;

struct Derives;

impl quote::ToTokens for Derives {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(quote! {
            #[derive(
                ::core::fmt::Debug,
                ::core::clone::Clone,
                ::core::cmp::PartialEq,
                ::doxa::__serde::Serialize,
                ::doxa::__serde::Deserialize,
            )]
            #[serde(crate = "::doxa::__serde")]
        });
    }
}

fn enum_items(
    ident: &Ident,
    docs: &TokenStream,
    repr: TokenStream,
    variants: &[TokenStream],
) -> TokenStream {
    quote! {
        #docs
        #DERIVES
        #repr
        #[non_exhaustive]
        pub enum #ident { #(#variants,)* }

        impl ::core::fmt::Display for #ident {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Debug::fmt(self, f)
            }
        }

        impl __Constraints for #ident {}
    }
}

fn string_enum(
    ident: &Ident,
    docs: &TokenStream,
    schema: &Schema,
    name: &str,
    at: &At<'_>,
) -> Result<TokenStream, GenerateError> {
    let mut variants = Vec::new();
    for v in &schema.values {
        let Scalar::Str(v) = v else {
            return Err(at.unsupported(name, "has a non-string enum value"));
        };
        let variant = Ident::new(&pascal(v), Span::call_site());
        variants.push(quote!(#[serde(rename = #v)] #variant));
    }
    Ok(enum_items(ident, docs, quote!(), &variants))
}

/// The checks on one field whose value is `v` at path `at`, as garde words them.
fn constraints(schema: &Schema, name: &str) -> TokenStream {
    let _ = name;
    let mut out = TokenStream::new();
    let push = |message: TokenStream| {
        quote! {
            out.0.push(::doxa::wire::FieldError { path: at.clone(), message: #message });
        }
    };
    if let Some(min) = schema.min_length {
        let m = push(quote!(::std::format!("length is lower than {}", #min)));
        out.extend(quote!(if (v.chars().count() as u64) < #min { #m }));
    }
    if let Some(max) = schema.max_length {
        let m = push(quote!(::std::format!("length is greater than {}", #max)));
        out.extend(quote!(if (v.chars().count() as u64) > #max { #m }));
    }
    if let Some(min) = schema.min_items {
        let m = push(quote!(::std::format!("length is lower than {}", #min)));
        out.extend(quote!(if (v.len() as u64) < #min { #m }));
    }
    if let Some(max) = schema.max_items {
        let m = push(quote!(::std::format!("length is greater than {}", #max)));
        out.extend(quote!(if (v.len() as u64) > #max { #m }));
    }
    // `minimum: 0` is how utoipa marks an unsigned type, which the type already enforces.
    if let Some(min) = schema.minimum.filter(|m| *m != 0.0) {
        let m = push(quote!(::std::format!("lower than {}", #min)));
        out.extend(quote!(if (*v as f64) < #min { #m }));
    }
    if let Some(max) = schema.maximum {
        let m = push(quote!(::std::format!("greater than {}", #max)));
        out.extend(quote!(if (*v as f64) > #max { #m }));
    }
    out
}

/// What every generated client starts with: the constraint walk and its `Validates` wrapper.
fn prelude(mapped: &[TokenStream]) -> TokenStream {
    quote! {
        /// The constraints a value's schema carries, checked as the client sends it.
        pub trait __Constraints {
            /// Push each failure under `path`.
            fn check_into(&self, path: &str, out: &mut ::doxa::wire::FieldErrors) {
                let _ = (path, out);
            }
        }

        fn __join(path: &str, field: &str) -> ::std::string::String {
            if path.is_empty() { field.to_owned() } else { ::std::format!("{path}.{field}") }
        }

        impl __Constraints for ::std::string::String {}
        impl __Constraints for bool {}
        impl __Constraints for u8 {}
        impl __Constraints for i32 {}
        impl __Constraints for i64 {}
        impl __Constraints for u32 {}
        impl __Constraints for u64 {}
        impl __Constraints for f32 {}
        impl __Constraints for f64 {}
        impl __Constraints for () {}
        impl __Constraints for ::doxa::wire::__Value {}
        #(impl __Constraints for #mapped {})*
        impl<T: __Constraints> __Constraints for ::std::vec::Vec<T> {
            fn check_into(&self, path: &str, out: &mut ::doxa::wire::FieldErrors) {
                for (i, v) in self.iter().enumerate() {
                    v.check_into(&::std::format!("{path}[{i}]"), out);
                }
            }
        }
        impl<T: __Constraints> __Constraints for ::core::option::Option<T> {
            fn check_into(&self, path: &str, out: &mut ::doxa::wire::FieldErrors) {
                if let ::core::option::Option::Some(v) = self {
                    v.check_into(path, out);
                }
            }
        }
        impl<T> __Constraints for ::std::collections::BTreeMap<::std::string::String, T> {}

        /// A body the client checks against its schema's constraints before sending.
        pub struct Spec<E>(pub E);

        impl<T: __Constraints> ::doxa::wire::Validates for Spec<::doxa::client::Json<T>> {
            type Value = T;
            fn check(value: &T) -> ::core::result::Result<(), ::doxa::wire::FieldErrors> {
                let mut out = ::doxa::wire::FieldErrors::default();
                value.check_into("", &mut out);
                if out.0.is_empty() { ::core::result::Result::Ok(()) } else { ::core::result::Result::Err(out) }
            }
        }

        impl<T: __Constraints> ::doxa::wire::Validates for Spec<::doxa::client::Form<T>> {
            type Value = T;
            fn check(value: &T) -> ::core::result::Result<(), ::doxa::wire::FieldErrors> {
                <Spec<::doxa::client::Json<T>> as ::doxa::wire::Validates>::check(value)
            }
        }
    }
}

/// Whether a component gets a type of its own rather than being written inline.
fn nameable(schema: &Schema) -> bool {
    or_null(schema).is_none()
        && (!schema.properties.is_empty() || !schema.one_of.is_empty() || !schema.values.is_empty())
}

/// `schema` without `null`, which a query string can't carry.
fn non_null(schema: Schema) -> Schema {
    if let Some(inner) = or_null(&schema) {
        return inner.clone();
    }
    let ty = match schema.ty {
        Some(super::spec::Types::Many(ts)) => Some(super::spec::Types::Many(
            ts.into_iter().filter(|t| t != "null").collect(),
        )),
        ty => ty,
    };
    Schema { ty, ..schema }
}

/// `X` in `oneOf: [{type: null}, X]`, as utoipa writes a nullable reference.
fn or_null(schema: &Schema) -> Option<&Schema> {
    let is_null = |s: &Schema| {
        s.reference.is_none()
            && s.one_of.is_empty()
            && s.ty.as_ref().map(super::spec::Types::split) == Some((None, true))
    };
    match schema.one_of.as_slice() {
        [a, b] if is_null(a) && !is_null(b) => Some(b),
        [a, b] if is_null(b) && !is_null(a) => Some(a),
        _ => None,
    }
}

fn integer(schema: &Schema) -> TokenStream {
    let unsigned = schema.minimum.is_some_and(|m| m >= 0.0);
    match (schema.format.as_deref(), unsigned) {
        (Some("int32"), true) => quote!(u32),
        (Some("int32"), false) => quote!(i32),
        (_, true) => quote!(u64),
        (_, false) => quote!(i64),
    }
}

fn doc(text: Option<&str>) -> TokenStream {
    match text {
        Some(t) => {
            let lines = t.lines().map(|l| format!(" {l}"));
            quote!(#(#[doc = #lines])*)
        }
        None => quote!(),
    }
}

pub(crate) fn parse_path(path: &str) -> Result<TokenStream, GenerateError> {
    TokenStream::from_str(path).map_err(|_| GenerateError::BadPath(path.to_owned()))
}

/// `WidgetEvent_Renamed`, `name_taken` and `listWidgets` as `WidgetEventRenamed`, `NameTaken`
/// and `ListWidgets`.
pub(crate) fn pascal(name: &str) -> String {
    let mut out = String::new();
    for part in name
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|p| !p.is_empty())
    {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    match out.chars().next() {
        Some(c) if c.is_ascii_digit() => format!("V{out}"),
        None => "Unnamed".into(),
        _ => out,
    }
}

/// `createdAt` as `created_at`; the flag says whether serde needs a rename.
pub(crate) fn field_ident(name: &str) -> (Ident, bool) {
    let mut snake = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                snake.push('_');
            }
            snake.push(c.to_ascii_lowercase());
        } else if c.is_ascii_alphanumeric() || c == '_' {
            snake.push(c);
        } else {
            snake.push('_');
        }
    }
    if snake.chars().next().is_none_or(|c| c.is_ascii_digit()) {
        snake.insert(0, '_');
    }
    let renamed = snake != name;
    let ident = match snake.as_str() {
        "self" | "super" | "crate" | "Self" => format_ident!("{snake}_"),
        s if KEYWORDS.contains(&s) => Ident::new_raw(s, Span::call_site()),
        s => Ident::new(s, Span::call_site()),
    };
    (
        ident,
        renamed || matches!(snake.as_str(), "self" | "super" | "crate"),
    )
}

const KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "dyn", "else", "enum", "extern", "false",
    "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
    "return", "static", "struct", "trait", "true", "type", "unsafe", "use", "where", "while",
    "abstract", "become", "box", "do", "final", "macro", "override", "priv", "typeof", "unsized",
    "virtual", "yield", "try", "gen",
];
