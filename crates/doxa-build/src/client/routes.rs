//! Each operation as a handler signature for `doxa::client::__as_client!`, so a generated
//! client's calls are made by the same stub a shared-source client's are.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use super::spec::{Location, Meta, Operation, Spec};
use super::types::{field_ident, pascal, At, Types};
use super::GenerateError;

/// Assets, keys and entity markers the signatures name, defined once.
#[derive(Default)]
struct Guards {
    assets: BTreeMap<String, TokenStream>,
    keys: BTreeMap<String, TokenStream>,
    /// How each header struct is sent, once per struct.
    headers: BTreeMap<String, TokenStream>,
}

/// Headers the client's layers own, which a call never takes as an argument.
const LAYER_HEADERS: &[&str] = &["authorization", "cookie", "content-type", "accept"];

impl Guards {
    fn asset(&mut self, name: &str, key: &str, entity: &str) -> Ident {
        let ident = format_ident!("{}", name);
        let key = format_ident!("{}", key);
        self.assets.entry(name.to_owned()).or_insert_with(|| {
            quote! {
                /// The guard a route takes this key through.
                pub struct #ident;
                impl ::doxa::wire::Keyed for #ident {
                    type Key = #key;
                    const ENTITY_TYPE: &'static str = #entity;
                    const PACKAGE: &'static str = ::core::env!("CARGO_PKG_NAME");
                }
            }
        });
        ident
    }

    /// A stand-in asset for a route that touches `entity` without being keyed by it.
    fn entity(&mut self, entity: &str) -> Ident {
        let ident = format_ident!("__{}Entity", pascal(entity));
        self.assets.entry(ident.to_string()).or_insert_with(|| {
            quote! {
                #[doc(hidden)]
                pub struct #ident;
                impl ::doxa::wire::Keyed for #ident {
                    type Key = ();
                    const ENTITY_TYPE: &'static str = #entity;
                    const PACKAGE: &'static str = ::core::env!("CARGO_PKG_NAME");
                }
            }
        });
        ident
    }

    /// A route key, as `route_key!` writes one.
    fn key(&mut self, name: &str, fields: Vec<(Ident, TokenStream)>) {
        let ident = format_ident!("{}", name);
        let names: Vec<String> = fields.iter().map(|(n, _)| n.to_string()).collect();
        let single = match fields.as_slice() {
            [(field, ty)] => quote! {
                impl<'a> ::doxa::client::Arg<#ident> for &'a str
                where
                    #ty: ::core::convert::From<&'a str>,
                {
                    fn into_arg(self) -> #ident {
                        #ident { #field: ::core::convert::From::from(self) }
                    }
                }
                impl ::doxa::client::Arg<#ident> for #ty {
                    fn into_arg(self) -> #ident {
                        #ident { #field: self }
                    }
                }
                impl ::doxa::client::Arg<#ident> for &#ty {
                    fn into_arg(self) -> #ident {
                        #ident { #field: ::core::clone::Clone::clone(self) }
                    }
                }
            },
            _ => quote!(),
        };
        let decls = fields.iter().map(|(n, t)| quote!(pub #n: #t));
        self.keys.entry(name.to_owned()).or_insert_with(|| {
            quote! {
                /// The key a route names one entity by.
                #[derive(
                    ::core::fmt::Debug,
                    ::core::clone::Clone,
                    ::core::cmp::PartialEq,
                    ::core::cmp::Eq,
                    ::core::hash::Hash,
                    ::doxa::__serde::Serialize,
                    ::doxa::__serde::Deserialize,
                )]
                #[serde(crate = "::doxa::__serde")]
                pub struct #ident { #(#decls,)* }

                impl ::doxa::wire::KeyNames for #ident {
                    const NAMES: &'static [&'static str] = &[#(#names),*];
                }

                #single
            }
        });
    }
}

/// The last segment of a Rust type name as `type_name` writes it.
fn short(type_name: &str) -> &str {
    let base = type_name.split('<').next().unwrap_or(type_name);
    base.rsplit("::").next().unwrap_or(base)
}

pub(crate) fn render(spec: &Spec, types: &mut Types<'_>) -> Result<TokenStream, GenerateError> {
    let mut guards = Guards::default();
    let mut modules: BTreeMap<Option<String>, (Option<Ident>, Vec<TokenStream>)> = BTreeMap::new();
    for (path, item) in &spec.paths {
        for (method, op) in item.operations() {
            let meta = op.doxa.as_ref();
            if meta.is_some_and(|m| !m.client) {
                continue;
            }
            let default = Meta {
                invalidates: true,
                ..Meta::default()
            };
            let route = match route(
                path,
                method,
                op,
                meta.unwrap_or(&default),
                types,
                &mut guards,
            ) {
                Ok(route) => route,
                Err(e) => {
                    types.record(e);
                    continue;
                }
            };
            let module = op.tags.first().map(|t| field_ident(t).0);
            modules
                .entry(module.as_ref().map(Ident::to_string))
                .or_insert_with(|| (module, Vec::new()))
                .1
                .push(route);
        }
    }
    let mut out = TokenStream::new();
    for (module, routes) in modules.into_values() {
        let calls = quote! {
            ::doxa::client::__as_client! { #(#routes)* }
        };
        out.extend(match module {
            Some(m) => {
                quote! {
                    pub mod #m {
                        #[allow(unused_imports)]
                        use super::*;
                        #calls
                    }
                }
            }
            None => calls,
        });
    }
    let assets = guards.assets.values();
    let keys = guards.keys.values();
    let headers = guards.headers.values();
    Ok(quote! {
        #(#keys)*
        #(#assets)*
        #(#headers)*
        #out
    })
}

fn route(
    path: &str,
    method: &str,
    op: &Operation,
    meta: &Meta,
    types: &mut Types<'_>,
    guards: &mut Guards,
) -> Result<TokenStream, GenerateError> {
    let id = op
        .operation_id
        .clone()
        .unwrap_or_else(|| format!("{method}_{}", path.replace(['/', '{', '}'], "_")));
    let name = field_ident(&id).0;
    let at = At {
        operation: &id,
        hint: pascal(&id),
        owner: None,
    };
    if let Some(identity) = &meta.identity {
        types.identity(identity);
    }

    let param = |name: &str| {
        op.parameters
            .iter()
            .find(|p| p.name == name && matches!(p.location, Location::Path | Location::Query))
    };
    let mut args = Vec::new();
    let mut keyed: BTreeSet<&str> = BTreeSet::new();

    // Entities the key doesn't cover still invalidate, through a guard on a stand-in asset.
    let key_entity = meta
        .key
        .as_ref()
        .and_then(|k| k.entity.clone())
        .or_else(|| meta.key.as_ref().and(meta.entities.first().cloned()));
    let mut seen_key_entity = false;
    for (i, entity) in meta.entities.iter().enumerate() {
        if Some(entity) == key_entity.as_ref() && !seen_key_entity {
            seen_key_entity = true;
            continue;
        }
        let marker = guards.entity(entity);
        let arg = format_ident!("__entity{i}");
        args.push(quote!(#arg: Granted<Many<#marker>>));
    }
    if let Some(key) = &meta.key {
        let mut fields = Vec::new();
        for n in &key.names {
            let ty = match param(n).and_then(|p| p.schema.as_ref()) {
                Some(s) => types.ty(s, &at.child_hint(n))?,
                None => quote!(::std::string::String),
            };
            fields.push((field_ident(n).0, ty));
            keyed.insert(n);
        }
        guards.key(short(&key.ty), fields);
        let entity = key_entity.as_deref().unwrap_or_default();
        let asset = guards.asset(short(&key.asset), short(&key.ty), entity);
        args.push(quote!(key: Granted<#asset>));
    }
    let guarded = !args.is_empty();
    if guarded && !meta.dry_run {
        args.push(quote!(#[server] __unchecked: ()));
    }

    // First, so the stub sees no unknown argument after the guard and keeps its dry run.
    let headers: Vec<_> = op
        .parameters
        .iter()
        .filter(|p| {
            p.location == Location::Header
                && !LAYER_HEADERS.contains(&p.name.to_ascii_lowercase().as_str())
        })
        .map(|p| {
            (
                p.name.clone(),
                p.schema.clone().unwrap_or_default(),
                p.required,
            )
        })
        .collect();
    if !headers.is_empty() {
        let ty = types.query(&format!("{}Headers", pascal(&id)), false, headers, &at);
        guards.headers.entry(ty.to_string()).or_insert_with(|| quote! {
            impl ::doxa::client::ClientArg for #ty {
                type Value = Self;
                fn apply(value: Self, out: &mut ::doxa::client::Outgoing) -> ::core::result::Result<(), ::std::string::String> {
                    out.header_fields(&value)
                }
            }
        });
        args.insert(0, quote!(headers: #ty));
    }

    let path_params: Vec<_> = op
        .parameters
        .iter()
        .filter(|p| p.location == Location::Path && !keyed.contains(p.name.as_str()))
        .collect();
    if !path_params.is_empty() {
        let tys = path_params
            .iter()
            .map(|p| match &p.schema {
                Some(s) => types.ty(s, &at.child_hint(&p.name)),
                None => Ok(quote!(::std::string::String)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        args.push(match tys.as_slice() {
            [one] => quote!(path: Path<#one>),
            many => quote!(path: Path<(#(#many,)*)>),
        });
    }

    let query: Vec<_> = op
        .parameters
        .iter()
        .filter(|p| p.location == Location::Query && !keyed.contains(p.name.as_str()))
        .map(|p| {
            (
                p.name.clone(),
                p.schema.clone().unwrap_or_default(),
                p.required,
            )
        })
        .collect();
    if !query.is_empty() {
        let ty = match &meta.query {
            Some(name) => types.query(name, true, query, &at),
            None => types.query(&format!("{}Query", pascal(&id)), false, query, &at),
        };
        args.push(quote!(query: Query<#ty>));
    }

    let json = |content: &str| {
        op.request_body
            .as_ref()
            .and_then(|b| b.content.get(content))
            .and_then(|m| m.schema.as_ref())
    };
    let body_kind = meta.body.clone().or_else(|| {
        op.request_body.as_ref().map(|b| {
            if b.content.contains_key("application/x-www-form-urlencoded") {
                "form".into()
            } else {
                "json".into()
            }
        })
    });
    match body_kind.as_deref() {
        Some("json") => {
            let schema = json("application/json").cloned().unwrap_or_default();
            let ty = types.ty(&schema, &at.child_hint("Body"))?;
            args.push(quote!(Spec(Json(body)): Spec<Json<#ty>>));
        }
        Some("form") => {
            let schema = json("application/x-www-form-urlencoded")
                .cloned()
                .unwrap_or_default();
            let ty = types.ty(&schema, &at.child_hint("Body"))?;
            args.push(quote!(Spec(Form(body)): Spec<Form<#ty>>));
        }
        Some("bytes") => args.push(quote!(body: Bytes)),
        Some("multipart") => args.push(quote!(form: Multipart)),
        _ => {}
    }

    let ret = response(op, meta, types, &at)?;
    let error = match &meta.error {
        Some(e) => Some(types.component(e, &at)?),
        None => {
            let bodies: Vec<&super::spec::Schema> = op
                .responses
                .iter()
                .filter(|(code, _)| !code.starts_with('2'))
                .filter_map(|(_, r)| r.content.get("application/json"))
                .filter_map(|m| m.schema.as_ref())
                .collect();
            types.error_of(&bodies, &format!("{}Error", pascal(&id)), &at)?
        }
    };
    let ret = match error {
        Some(e) => quote!(::core::result::Result<#ret, #e>),
        None => ret,
    };

    let docs = [op.summary.as_deref(), op.description.as_deref()]
        .into_iter()
        .flatten()
        .flat_map(str::lines)
        .map(|l| format!(" {l}"));
    let method = format_ident!("{method}");
    let op_id = (name != id.as_str()).then(|| quote!(, operation_id = #id));
    let invalidates = (!meta.invalidates).then(|| quote!(, invalidates = false));
    Ok(quote! {
        #(#[doc = #docs])*
        #[#method(#path #op_id #invalidates)]
        pub async fn #name(#(#args),*) -> #ret { ::core::unreachable!() }
    })
}

/// The success response, as the stub reads a handler's return type.
fn response(
    op: &Operation,
    meta: &Meta,
    types: &mut Types<'_>,
    at: &At<'_>,
) -> Result<TokenStream, GenerateError> {
    let ok = op
        .responses
        .iter()
        .filter(|(code, _)| code.starts_with('2'))
        .min_by_key(|(code, _)| code.as_str());
    let Some((code, response)) = ok else {
        return Ok(quote!(StatusCode));
    };
    if meta.stream.is_some() || response.content.contains_key("text/event-stream") {
        let schema = response
            .content
            .get("text/event-stream")
            .and_then(|m| m.schema.clone())
            .unwrap_or_default();
        let ty = types.ty(&schema, &at.child_hint("Event"))?;
        return Ok(quote!(SseStream<#ty>));
    }
    if let Some(schema) = response
        .content
        .get("application/json")
        .and_then(|m| m.schema.as_ref())
    {
        let ty = types.ty(schema, &at.child_hint("Response"))?;
        return Ok(match code.as_str() {
            "200" => quote!(Json<#ty>),
            _ => quote!((StatusCode, Json<#ty>)),
        });
    }
    if response
        .content
        .keys()
        .any(|c| c == "application/octet-stream")
    {
        return Ok(quote!(Attachment));
    }
    if response.content.keys().any(|c| c.starts_with("text/")) {
        return Ok(quote!(String));
    }
    Ok(quote!(StatusCode))
}

impl At<'_> {
    fn child_hint(&self, suffix: &str) -> At<'_> {
        self.child(format!("{}{}", self.hint, pascal(suffix)))
    }
}
