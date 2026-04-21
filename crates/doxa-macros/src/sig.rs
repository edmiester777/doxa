//! Function-signature inference for the method shortcut macros.
//!
//! Walks an [`syn::ItemFn`] and extracts the information that would
//! otherwise have to be re-declared inside the `#[utoipa::path]`
//! attribute:
//!
//! - **`request_body`** — the inner type of the first `Json<T>` extractor
//!   parameter (searched through recognized transparent wrappers such as
//!   `Valid<Json<T>>`).
//! - **Path parameters** — the route template is parsed for `{name}` segments
//!   and the list is passed to the path probes so scalar, tuple, and
//!   struct-form `Path<T>` all surface via trait dispatch. URL-template names
//!   are authoritative, not the handler's binding names.
//! - **Everything else** — every handler argument (including wrapped extractors
//!   such as `Valid<Query<T>>`) is emitted as an entry into an auto-generated
//!   per-handler `IntoParams` struct that dispatches to the [`DocQueryParams`]
//!   / [`DocPathParams`] / [`DocHeaderParams`] role traits via autoref
//!   specialization. Types that do not implement any of those traits silently
//!   contribute nothing.
//! - **Success response** — the inner type of the return value. Recognized
//!   shapes:
//!   - `Json<T>` → status 200, body `T`
//!   - `(StatusCode, Json<T>)` → status 201, body `T` (the tuple form is
//!     conventionally used for `POST` creates, so 201 is the right default;
//!     callers can override with explicit `responses(...)`)
//!   - `Result<Inner, E>` where `Inner` is one of the above
//! - **Error responses** — the error type `E` from a `Result<_, E>` return is
//!   folded into the operation's `responses(...)` as a reference, expanding to
//!   `<E as IntoResponses>::responses()` at `utoipa::path` expansion time.
//!
//! Extension mechanism: third-party wrappers that are semantically
//! transparent (auth guards, validators, tenant scopers) opt into the
//! doc trait forwarding with one blanket impl per role — no macro
//! changes needed. See the `DocXxx` traits in `doxa` for the
//! full pattern.
//!
//! Explicit overrides always win: if the user already supplied
//! `request_body = ...`, `params(...)`, or `responses(...)`, the macro
//! emits only the user's version for that key.

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    spanned::Spanned, FnArg, GenericArgument, ItemFn, PathArguments, ReturnType, Type, TypePath,
};

/// What the signature parser was able to infer from the handler.
#[derive(Default)]
pub struct InferredAttrs {
    /// Inner type of the first `Json<T>` parameter, searched through
    /// recognized transparent wrappers.
    pub request_body: Option<Type>,
    /// Full argument types in declaration order. Emitted into the
    /// per-handler `IntoParams` dispatch struct for trait-based
    /// contribution.
    pub arg_types: Vec<Type>,
    /// Full return type, if present. Emitted as the generic argument to
    /// a `ResponseBodyContribution<ReturnType>` probe in the generated
    /// `ApidocHandlerOps` and `ApidocHandlerSchemas` impls — the probe
    /// dispatches at runtime through [`crate::DocResponseBody`][drb] so
    /// types that implement it (e.g. [`axum::Json<T>`][axj],
    /// [`doxa::SseStream<E, S>`][sse], [`Result<Ok, Err>`]
    /// when `Ok: DocResponseBody`) contribute the success response
    /// while types that do not silently no-op. `Result<_, E>` still has
    /// its error half extracted syntactically for
    /// `responses(E)` emission where `E: utoipa::IntoResponses`.
    ///
    /// [drb]: ../../doxa/trait.DocResponseBody.html
    /// [axj]: https://docs.rs/axum/latest/axum/struct.Json.html
    /// [sse]: ../../doxa/struct.SseStream.html
    pub return_type: Option<Type>,
    /// Inferred error type — folded into `responses(...)` as an
    /// `IntoResponses` reference.
    pub error_type: Option<Type>,
    /// Marker types for typed-header extractors found in the
    /// signature (e.g. `Header<MyAuth>` → `MyAuth`). Each entry is
    /// emitted as `::doxa::DocHeaderEntry<MarkerType>` inside
    /// the synthesized `params(...)` block. Kept for the existing
    /// `headers(...)` macro-argument path; new `Header<H>` extractors
    /// also flow through the trait-based dispatch, with dedupe
    /// handled at emit time.
    pub header_marker_types: Vec<Type>,
}

/// Walk a function and infer everything we can from its signature.
pub fn infer(item_fn: &ItemFn) -> InferredAttrs {
    let mut inferred = InferredAttrs::default();

    for input in &item_fn.sig.inputs {
        let FnArg::Typed(pat_type) = input else {
            continue; // `&self` etc. — handlers are free functions
        };

        // Record the arg's full type for trait-based contribution,
        // except `Header<H>` extractors — those are emitted via the
        // existing `DocHeaderEntry<H>` path (see below) so routing
        // them through trait dispatch as well would double-emit the
        // header parameter.
        if !matches!(wrapper_and_inner(&pat_type.ty), Some(("Header", _))) {
            inferred.arg_types.push((*pat_type.ty).clone());
        }

        // Recognize syntactic shapes that still need special
        // treatment.
        //
        // 1. `Json<T>` / wrapped `Json<T>` — request body inference.
        if inferred.request_body.is_none() {
            if let Some(body_ty) = find_json_inner(&pat_type.ty) {
                inferred.request_body = Some(body_ty.clone());
            }
        }

        // 2. `Header<H>` — keep the existing `DocHeaderEntry<H>` emission path for
        //    parity with `headers(...)` macro argument. Trait-based dispatch also
        //    handles it, but the emitted `DocHeaderEntry<H>` runs first and any
        //    duplicate from the trait path is filtered out by utoipa (headers are
        //    matched by name via [`apply_headers_to_operation`][h]).
        //
        // [h]: ../../doxa/fn.apply_headers_to_operation.html
        if let Some(("Header", inner)) = wrapper_and_inner(&pat_type.ty) {
            inferred.header_marker_types.push(inner.clone());
        }
    }

    if let ReturnType::Type(_, ret) = &item_fn.sig.output {
        // Preserve the full return type so the per-handler probe can
        // dispatch through `DocResponseBody`. The error half is still
        // extracted syntactically because utoipa's `responses(E)`
        // argument expects a type reference at macro expansion time.
        //
        // Replace any nested `impl Trait` with the unit type `()`. Our
        // `DocResponseBody` blanket impls are unbounded on the stream
        // / future generics, so `SseStream<E, ()>` dispatches the same
        // way as `SseStream<E, impl Stream<…>>`, and `()` is a valid
        // type in generic position where `impl Trait` is not.
        inferred.return_type = Some(strip_impl_trait((**ret).clone()));
        let (_success_inner, error) = unwrap_result(ret);
        inferred.error_type = error;
    }

    inferred
}

/// Recursively replace every `impl Trait` occurrence inside `ty` with
/// the unit type `()`.
///
/// `impl Trait` is a non-nameable type introduced by the compiler and
/// is not allowed in generic-argument position, so we can't hand the
/// literal return type of a function that uses it to a
/// `Contribution::<ReturnType>` probe. Substituting `()` preserves the
/// outer wrapper (which carries the trait impl we want to dispatch
/// to) while replacing any unreachable inner generics with something
/// the compiler will accept.
fn strip_impl_trait(ty: Type) -> Type {
    match ty {
        Type::ImplTrait(_) => Type::Tuple(syn::TypeTuple {
            paren_token: syn::token::Paren::default(),
            elems: syn::punctuated::Punctuated::new(),
        }),
        Type::Path(mut tp) => {
            for seg in tp.path.segments.iter_mut() {
                if let PathArguments::AngleBracketed(args) = &mut seg.arguments {
                    for arg in args.args.iter_mut() {
                        if let GenericArgument::Type(inner) = arg {
                            *inner = strip_impl_trait(inner.clone());
                        }
                    }
                }
            }
            Type::Path(tp)
        }
        Type::Tuple(mut tt) => {
            for inner in tt.elems.iter_mut() {
                *inner = strip_impl_trait(inner.clone());
            }
            Type::Tuple(tt)
        }
        Type::Array(mut ta) => {
            ta.elem = Box::new(strip_impl_trait(*ta.elem));
            Type::Array(ta)
        }
        Type::Reference(mut tr) => {
            tr.elem = Box::new(strip_impl_trait(*tr.elem));
            Type::Reference(tr)
        }
        Type::Ptr(mut tp) => {
            tp.elem = Box::new(strip_impl_trait(*tp.elem));
            Type::Ptr(tp)
        }
        Type::Paren(mut tp) => {
            tp.elem = Box::new(strip_impl_trait(*tp.elem));
            Type::Paren(tp)
        }
        Type::Group(mut tg) => {
            tg.elem = Box::new(strip_impl_trait(*tg.elem));
            Type::Group(tg)
        }
        other => other,
    }
}

/// Walk a type and collect every nested generic argument that appears
/// anywhere inside it, at any depth. Does **not** include `ty` itself.
///
/// Used by the inferred `ApidocHandlerSchemas::collect` impl to route
/// each nested type through a
/// [`GenericArgSchemaContribution`](../../doxa/__private/struct.GenericArgSchemaContribution.html)
/// probe so types buried inside generic wrappers (e.g. `SourceSummary`
/// inside `Paginated<SourceSummary>`) get registered on
/// `components.schemas`. Types that do not implement `ToSchema`
/// silently no-op via the probe's depth-1 fallback — so emitting
/// probes for wrapper types like `Json`, `Result`, `Vec`, `Option`,
/// and tuples is safe.
///
/// The recursion follows every shape that can contain a type inside
/// generic angle brackets or element position: path-type generics,
/// tuples, arrays, references, pointers, parens, and grouping nodes.
/// `impl Trait` and other non-nominal shapes are skipped because they
/// have already been normalized to `()` by [`strip_impl_trait`].
fn collect_nested_type_args(ty: &Type, out: &mut Vec<Type>) {
    match ty {
        Type::Path(tp) => {
            for seg in &tp.path.segments {
                if let PathArguments::AngleBracketed(args) = &seg.arguments {
                    for arg in &args.args {
                        if let GenericArgument::Type(inner) = arg {
                            out.push(inner.clone());
                            collect_nested_type_args(inner, out);
                        }
                    }
                }
            }
        }
        Type::Tuple(tt) => {
            for elem in &tt.elems {
                out.push(elem.clone());
                collect_nested_type_args(elem, out);
            }
        }
        Type::Array(ta) => {
            out.push((*ta.elem).clone());
            collect_nested_type_args(&ta.elem, out);
        }
        Type::Reference(tr) => collect_nested_type_args(&tr.elem, out),
        Type::Ptr(tp) => collect_nested_type_args(&tp.elem, out),
        Type::Paren(tp) => collect_nested_type_args(&tp.elem, out),
        Type::Group(tg) => collect_nested_type_args(&tg.elem, out),
        _ => {}
    }
}

/// Match `Wrapper<Inner>` and return `("Wrapper", Inner)`. Recognizes
/// both bare `Json<T>` and qualified `axum::Json<T>` / `axum::extract::Json<T>`
/// by inspecting the final segment.
fn wrapper_and_inner(ty: &Type) -> Option<(&'static str, &Type)> {
    let TypePath { path, .. } = match ty {
        Type::Path(tp) => tp,
        _ => return None,
    };
    let last = path.segments.last()?;
    let wrapper = match last.ident.to_string().as_str() {
        "Json" => "Json",
        "Path" => "Path",
        "Query" => "Query",
        "Header" => "Header",
        _ => return None,
    };
    let PathArguments::AngleBracketed(args) = &last.arguments else {
        return None;
    };
    let inner = args.args.iter().find_map(|arg| match arg {
        GenericArgument::Type(t) => Some(t),
        _ => None,
    })?;
    Some((wrapper, inner))
}

/// Walk through single-generic wrappers (Valid, Authenticated, …) to
/// find the inner type of the first `Json<T>` reached. Returns `None`
/// if no `Json` is present in the type tree.
fn find_json_inner(ty: &Type) -> Option<&Type> {
    // Direct Json<T>?
    if let Some(("Json", inner)) = wrapper_and_inner(ty) {
        return Some(inner);
    }
    // Otherwise, if this type is a wrapper with a single generic
    // argument, recurse into it.
    let Type::Path(TypePath { path, .. }) = ty else {
        return None;
    };
    let last = path.segments.last()?;
    let PathArguments::AngleBracketed(args) = &last.arguments else {
        return None;
    };
    for arg in &args.args {
        if let GenericArgument::Type(inner_ty) = arg {
            if let Some(found) = find_json_inner(inner_ty) {
                return Some(found);
            }
        }
    }
    None
}

/// Parse `{name}` segments from a route template, in order.
///
/// The route string uses the axum / OpenAPI convention of
/// `{identifier}` for path parameters. Anything not matching that
/// exactly (including the wildcard `{*rest}` form) is skipped so the
/// emission stays conservative.
pub fn parse_path_names(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let start = i + 1;
            if let Some(end_rel) = path[start..].find('}') {
                let end = start + end_rel;
                let name = &path[start..end];
                // Skip wildcards and empty names.
                if !name.is_empty() && !name.starts_with('*') {
                    out.push(name.to_string());
                }
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Returns `(Some(success_inner), Some(error_type))` for a `Result<S, E>`
/// return type. Returns `(Some(ty), None)` if the return type is not a
/// `Result`. Returns `(None, None)` if there is no return type.
fn unwrap_result(ty: &Type) -> (Option<Type>, Option<Type>) {
    let Type::Path(TypePath { path, .. }) = ty else {
        return (Some(ty.clone()), None);
    };
    let Some(last) = path.segments.last() else {
        return (Some(ty.clone()), None);
    };
    // Accept both `Result` and `ApiResult` (the doxa alias).
    let is_result = last.ident == "Result" || last.ident == "ApiResult";
    if !is_result {
        return (Some(ty.clone()), None);
    }
    let PathArguments::AngleBracketed(args) = &last.arguments else {
        return (Some(ty.clone()), None);
    };
    let mut iter = args.args.iter().filter_map(|arg| match arg {
        GenericArgument::Type(t) => Some(t.clone()),
        _ => None,
    });
    let success = iter.next();
    let error = iter.next();
    (success, error)
}

/// Tokens produced by the inference layer, split into:
/// - `pre_items` — free-standing items (the per-handler dispatch struct + its
///   `IntoParams` impl) that must appear as siblings of the `#[utoipa::path]`
///   attribute so `params(...)` can refer to them.
/// - `attr_additions` — tokens to splice into the `#[utoipa::path(...)]`
///   argument list (comma-prefixed, ready to concatenate after the
///   caller-provided arguments).
pub struct InferredTokens {
    pub pre_items: TokenStream,
    pub attr_additions: TokenStream,
}

impl InferredAttrs {
    /// Render the inferred attributes to (items, attr-arg tokens).
    ///
    /// `fn_ident` is used to name the per-handler dispatch struct so
    /// multiple handlers can coexist in the same module without ident
    /// collisions. `path_param_names` are the `{name}` segments parsed
    /// from the route template by [`parse_path_names`].
    pub fn into_tokens(
        self,
        fn_ident: &syn::Ident,
        path_param_names: &[String],
        user_keys: &[&str],
    ) -> InferredTokens {
        let mut attr_additions = TokenStream::new();
        let mut pre_items = TokenStream::new();

        // --- request_body ---------------------------------------------------
        if !user_keys.contains(&"request_body") {
            if let Some(ty) = &self.request_body {
                attr_additions.extend(quote! { , request_body = #ty });
            }
        }

        // All `pre_items` attach impls to utoipa's own `__path_<fn>`
        // struct (generated by `#[utoipa::path]`). Callers already
        // import that struct via `use module::__path_<fn>` to make
        // `routes!(fn)` work, so hanging our impls off the same type
        // avoids a second set of imports per handler.
        let path_struct_ident = syn::Ident::new(&format!("__path_{}", fn_ident), fn_ident.span());
        let arg_types_for_schemas = self.arg_types.clone();

        // Error-type schema registration — autoref-probed so
        // handlers whose error type does not implement `ToSchema`
        // (or who have no error type) still compile. When present,
        // calling `ToSchema::schemas` transitively pulls every
        // schema the error body references (e.g. `MissingDecision`
        // from a tagged `MigrateError` variant) — utoipa's own
        // `IntoResponses`-based collection does not walk these (see
        // `utoipa_gen::path::response::Response::IntoResponses`
        // which returns `ResponseComponentSchemaIter::Empty`).
        let error_schemas_tt = if let Some(err_ty) = &self.error_type {
            quote! {
                {
                    #[allow(unused_imports)]
                    use ::doxa::__private::{
                        BareSchemaImplementedAdhoc as _,
                        BareSchemaMissingAdhoc as _,
                    };
                    ::doxa::__private::BareSchemaContribution::<
                        #err_ty,
                    >::new()
                    .__collect(__out);
                }
            }
        } else {
            quote! {}
        };

        // Generic-argument schema registration. For every type
        // parameter that appears anywhere inside the handler's return
        // type, emit a `GenericArgSchemaContribution` probe so the
        // type's root schema lands on `components.schemas`. Utoipa's
        // `ToSchema` derive filters type-parameter fields into its
        // `generic_references` bucket and emits only the recursive
        // `<T as ToSchema>::schemas(out)` call for them — never the
        // `(name, schema)` pair — so a concrete instantiation like
        // `Paginated<SourceSummary>` where `SourceSummary` is never
        // returned directly anywhere else leaves a dangling
        // `$ref: #/components/schemas/SourceSummary` in the spec.
        // The probe's depth-1 fallback no-ops for types that don't
        // implement `ToSchema + PartialSchema`, so emitting probes
        // for wrappers like `Json`, `Result`, `Vec`, and `Option` is
        // safe.
        let generic_arg_schemas_tt = if let Some(ret_ty) = &self.return_type {
            let mut nested: Vec<Type> = Vec::new();
            collect_nested_type_args(ret_ty, &mut nested);
            let probes = nested.iter().map(|ty| {
                quote! {
                    {
                        #[allow(unused_imports)]
                        use ::doxa::__private::{
                            GenericArgSchemaImplementedAdhoc as _,
                            GenericArgSchemaMissingAdhoc as _,
                        };
                        ::doxa::__private::GenericArgSchemaContribution::<
                            #ty,
                        >::new()
                        .__collect(__out);
                    }
                }
            });
            quote! { #(#probes)* }
        } else {
            quote! {}
        };

        // Response-body trait dispatch. When the handler's return type
        // implements `DocResponseBody` (covers `axum::Json<T>`,
        // `SseStream<E, _>`, `Result<Ok, _>` where `Ok: DocResponseBody`,
        // and any user-defined wrapper), the depth-0 autoref impl
        // contributes the success response at augment time; otherwise
        // the depth-1 fallback is a no-op. Having the type be an
        // `Option<Type>` accommodates handlers with no explicit return
        // (`-> ()` or function body only) — those get the no-op
        // fallback.
        let (response_body_ops_tt, response_body_schemas_tt) = match &self.return_type {
            Some(ret_ty) => (
                quote! {
                    {
                        #[allow(unused_imports)]
                        use ::doxa::__private::{
                            ResponseBodyImplementedAdhoc as _,
                            ResponseBodyMissingAdhoc as _,
                        };
                        ::doxa::__private::ResponseBodyContribution::<
                            #ret_ty,
                        >::new()
                        .__describe(__op, &mut __schemas);
                    }
                },
                // Parallel call from `ApidocHandlerSchemas::collect` so
                // the success body's schema lands in components.schemas.
                // The schemas vec from the caller is already named
                // `__out` in that impl, not `__schemas`.
                quote! {
                    {
                        #[allow(unused_imports)]
                        use ::doxa::__private::{
                            ResponseBodyImplementedAdhoc as _,
                            ResponseBodyMissingAdhoc as _,
                        };
                        // The probe wants (op, schemas); we only need
                        // schemas here, so pass a throwaway operation
                        // and let the impl mutate it without effect.
                        let mut __throwaway_op =
                            ::utoipa::openapi::path::OperationBuilder::new().build();
                        ::doxa::__private::ResponseBodyContribution::<
                            #ret_ty,
                        >::new()
                        .__describe(&mut __throwaway_op, __out);
                    }
                },
            ),
            None => (quote! {}, quote! {}),
        };

        // The `ApidocHandlerOps` impl mutates each operation owned
        // by this handler with per-extractor security/permission
        // contributions (anything implementing
        // `DocOperationSecurity`). Always emitted so the extended
        // `routes!` macro can unconditionally call
        // `<__path_<fn> as ApidocHandlerOps>::augment(...)`. When no
        // argument implements `DocOperationSecurity`, every probe
        // resolves to the autoref-fallback no-op and the operation
        // is left unchanged.
        let arg_types_for_ops = self.arg_types.clone();
        pre_items.extend(quote! {
            impl ::doxa::ApidocHandlerOps for #path_struct_ident {
                fn augment(
                    __paths: &mut ::utoipa::openapi::path::Paths,
                ) {
                    let __path_str = <Self as ::utoipa::Path>::path();
                    let __methods = <Self as ::utoipa::Path>::methods();
                    let __item = match __paths.paths.get_mut(&__path_str) {
                        ::core::option::Option::Some(item) => item,
                        ::core::option::Option::None => return,
                    };
                    for __method in __methods {
                        let __op = match ::doxa::operation_for_method_mut(
                            __item, __method,
                        ) {
                            ::core::option::Option::Some(op) => op,
                            ::core::option::Option::None => continue,
                        };
                        #(
                            {
                                #[allow(unused_imports)]
                                use ::doxa::__private::{
                                    OpSecurityImplementedAdhoc as _,
                                    OpSecurityMissingAdhoc as _,
                                };
                                ::doxa::__private::OpSecurityContribution::<
                                    #arg_types_for_ops,
                                >::new()
                                .__describe(__op);
                            }
                        )*
                        // Schemas referenced by the response body are
                        // already collected via `ApidocHandlerSchemas`
                        // below (same trait impl, second entry point);
                        // this scratch vec is passed only because the
                        // dispatch signature requires it.
                        let mut __schemas: ::std::vec::Vec<(
                            ::std::string::String,
                            ::utoipa::openapi::RefOr<::utoipa::openapi::schema::Schema>,
                        )> = ::std::vec::Vec::new();
                        #response_body_ops_tt
                        drop(__schemas);
                    }
                }
            }
        });

        // The `ApidocHandlerSchemas` impl is always emitted so the
        // extended `routes!` macro can unconditionally call
        // `<__path_<fn> as ApidocHandlerSchemas>::collect(...)`
        // regardless of whether the handler has arguments or
        // whether the caller supplied their own `params(...)`.
        pre_items.extend(quote! {
            impl ::doxa::ApidocHandlerSchemas for #path_struct_ident {
                fn collect(
                    __out: &mut ::std::vec::Vec<(
                        ::std::string::String,
                        ::utoipa::openapi::RefOr<::utoipa::openapi::schema::Schema>,
                    )>,
                ) {
                    let _ = &__out;
                    #(
                        {
                            #[allow(unused_imports)]
                            use ::doxa::__private::{
                                InnerSchemaImplementedAdhoc as _,
                                InnerSchemaMissingAdhoc as _,
                            };
                            ::doxa::__private::InnerSchemaContribution::<
                                #arg_types_for_schemas,
                            >::new()
                            .__collect(__out);
                        }
                    )*
                    #error_schemas_tt
                    #response_body_schemas_tt
                    #generic_arg_schemas_tt
                }
            }
        });

        // --- params ---------------------------------------------------------
        if !user_keys.contains(&"params") {
            let mut entries: Vec<TokenStream> = Vec::new();

            // Header markers (from `Header<H>` extractors and the
            // `headers(...)` macro argument) continue to flow through
            // `DocHeaderEntry<H>` for symmetry with layer-side
            // `HeaderParam::typed`. Trait dispatch dedupes by header
            // name at spec-build time.
            for ty in &self.header_marker_types {
                entries.push(quote! { ::doxa::DocHeaderEntry<#ty> });
            }

            if !self.arg_types.is_empty() {
                let arg_types = &self.arg_types;
                let names_lits: Vec<_> = path_param_names.iter().map(|s| s.as_str()).collect();

                // Build the IntoParams body: one adhoc-dispatched
                // `__collect()` call per arg per role, extending a
                // shared Vec. Imports live inside an inner block so
                // they don't leak to the caller's scope. Path probes
                // receive the URL-template `{name}` list.
                pre_items.extend(quote! {
                    impl ::utoipa::IntoParams for #path_struct_ident {
                        fn into_params(
                            _: impl ::core::ops::Fn()
                                -> ::core::option::Option<::utoipa::openapi::path::ParameterIn>,
                        ) -> ::std::vec::Vec<::utoipa::openapi::path::Parameter> {
                            const __PATH_NAMES: &[&'static str] = &[#(#names_lits),*];
                            let mut __out: ::std::vec::Vec<::utoipa::openapi::path::Parameter> =
                                ::std::vec::Vec::new();
                            #(
                                {
                                    #[allow(unused_imports)]
                                    use ::doxa::__private::{
                                        QueryParamsImplementedAdhoc as _,
                                        QueryParamsMissingAdhoc as _,
                                    };
                                    __out.extend(
                                        ::doxa::__private::QueryParamContribution::<
                                            #arg_types,
                                        >::new()
                                        .__collect(),
                                    );
                                }
                                {
                                    #[allow(unused_imports)]
                                    use ::doxa::__private::{
                                        PathParamsImplementedAdhoc as _,
                                        PathParamsMissingAdhoc as _,
                                    };
                                    __out.extend(
                                        ::doxa::__private::PathParamContribution::<
                                            #arg_types,
                                        >::new()
                                        .__collect(__PATH_NAMES),
                                    );
                                }
                                {
                                    #[allow(unused_imports)]
                                    use ::doxa::__private::{
                                        PathScalarImplementedAdhoc as _,
                                        PathScalarMissingAdhoc as _,
                                    };
                                    __out.extend(
                                        ::doxa::__private::PathScalarContribution::<
                                            #arg_types,
                                        >::new()
                                        .__collect(__PATH_NAMES),
                                    );
                                }
                                {
                                    #[allow(unused_imports)]
                                    use ::doxa::__private::{
                                        HeaderParamsImplementedAdhoc as _,
                                        HeaderParamsMissingAdhoc as _,
                                    };
                                    __out.extend(
                                        ::doxa::__private::HeaderParamContribution::<
                                            #arg_types,
                                        >::new()
                                        .__collect(),
                                    );
                                }
                            )*
                            __out
                        }
                    }
                });

                entries.push(quote! { #path_struct_ident });
            }

            if !entries.is_empty() {
                attr_additions.extend(quote! { , params(#(#entries),*) });
            }
        }

        // --- responses ------------------------------------------------------
        //
        // Success responses are contributed via `DocResponseBody` at
        // augment time (see `response_body_ops_tt` above). Only the
        // error half is emitted into `responses(E)` because utoipa
        // expects the error type as a macro-time argument for its
        // `IntoResponses`-driven response collection.
        if !user_keys.contains(&"responses") {
            if let Some(error) = &self.error_type {
                attr_additions.extend(quote! { , responses(#error) });
            }
        }

        InferredTokens {
            pre_items,
            attr_additions,
        }
    }
}

/// Best-effort: walk an extra-args list and return the set of top-level
/// keys the caller already supplied (`request_body`, `params`,
/// `responses`, etc.) so the inference layer knows which fields to
/// suppress.
pub fn collect_user_keys(extra: &[syn::Meta]) -> Vec<&'static str> {
    let mut keys = Vec::new();
    for meta in extra {
        let path = meta.path();
        if path.is_ident("request_body") {
            keys.push("request_body");
        } else if path.is_ident("params") {
            keys.push("params");
        } else if path.is_ident("responses") {
            keys.push("responses");
        } else if path.is_ident("security") {
            keys.push("security");
        } else if path.is_ident("tag") {
            keys.push("tag");
        } else if path.is_ident("tags") {
            keys.push("tag"); // suppress tag inference — `tags(...)` covers it
        } else if path.is_ident("operation_id") {
            keys.push("operation_id");
        } else if path.is_ident("description") {
            keys.push("description");
        } else if path.is_ident("summary") {
            keys.push("summary");
        }
    }
    keys
}

// Suppress the unused-import warning when none of the helper traits
// from `Spanned` / `ToTokens` are referenced from the public API. They
// are used in match patterns and span propagation throughout the file.
#[allow(dead_code)]
fn _trait_anchors(t: &Type, _t2: TokenStream) {
    let _ = t.span();
    let _ = t.to_token_stream();
}
