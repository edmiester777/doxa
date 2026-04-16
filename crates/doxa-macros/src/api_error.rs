//! Implementation of `#[derive(ApiError)]`.
//!
//! Generates two trait implementations from a single per-variant
//! declaration:
//!
//! 1. `axum::response::IntoResponse` — converts the enum into an HTTP response
//!    with the variant's declared status code and an [`ApiErrorBody`] envelope
//!    populated from the variant's `code`, `Display`, and typed payload.
//! 2. `utoipa::IntoResponses` — produces an OpenAPI response map with
//!    per-status-code typed envelope schemas. Each status group constrains its
//!    `code` field to the codes present at that status and its `error` field to
//!    a `oneOf` of only the variants at that status.

use proc_macro2::TokenStream;
use quote::quote;
use std::collections::BTreeMap;
use syn::{
    parse2, Attribute, Data, DeriveInput, Error, Expr, ExprLit, Fields, Ident, Lit, LitInt, LitStr,
    Result, Type, Variant,
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
                "ApiError can only be derived for enums",
            ))
        }
    };

    let variants = data
        .variants
        .iter()
        .map(parse_variant)
        .collect::<Result<Vec<_>>>()?;

    if variants.is_empty() {
        return Err(Error::new_spanned(
            &derive_input,
            "ApiError requires at least one variant with #[api(...)]",
        ));
    }

    let into_response = generate_into_response(&enum_name, &variants);
    let into_responses = generate_into_responses(&enum_name, &variants);
    let audit_outcome = generate_audit_outcome(&enum_name, &variants);

    Ok(quote! {
        #into_response
        #into_responses
        #audit_outcome
    })
}

/// Parsed metadata from one enum variant.
struct ParsedVariant {
    ident: Ident,
    shape: VariantShape,
    status: u16,
    code: String,
    /// Audit outcome declared via `#[api(outcome = "denied")]`.
    /// Defaults to `"error"` when omitted.
    outcome: Option<String>,
}

enum VariantShape {
    /// Unit variant: `Foo`
    Unit,
    /// Single unnamed field: `Foo(T)`. Stores the inner type for schema
    /// generation via `<T as PartialSchema>::schema()`.
    SingleField(Box<Type>),
    /// Named fields or multiple unnamed fields.
    Other,
}

fn parse_variant(variant: &Variant) -> Result<ParsedVariant> {
    let attr = find_api_attr(&variant.attrs).ok_or_else(|| {
        Error::new_spanned(
            variant,
            "every variant must have an #[api(status = ..., code = \"...\")] attribute",
        )
    })?;

    let args = parse_api_attr_args(attr, &variant.ident)?;

    let shape = match &variant.fields {
        Fields::Unit => VariantShape::Unit,
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            VariantShape::SingleField(Box::new(fields.unnamed[0].ty.clone()))
        }
        _ => VariantShape::Other,
    };

    Ok(ParsedVariant {
        ident: variant.ident.clone(),
        shape,
        status: args.status,
        code: args.code,
        outcome: args.outcome,
    })
}

/// Find the per-variant declaration attribute. Both `#[api(...)]` (the
/// canonical short form) and `#[api_error(...)]` (legacy alias) are
/// accepted; new code should use `#[api(...)]`.
fn find_api_attr(attrs: &[Attribute]) -> Option<&Attribute> {
    attrs
        .iter()
        .find(|a| a.path().is_ident("api") || a.path().is_ident("api_error"))
}

/// Parse `#[api(status = N, code = "...", outcome = "...")]`. The `code`
/// and `outcome` fields are optional — `code` defaults to a snake_case
/// version of the variant identifier, and `outcome` is only parsed when
/// the `audit` feature is enabled.
fn parse_api_attr_args(attr: &Attribute, variant_ident: &Ident) -> Result<ApiAttrArgs> {
    let mut status: Option<u16> = None;
    let mut code: Option<String> = None;
    let mut outcome: Option<String> = None;

    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("status") {
            let value: Expr = meta.value()?.parse()?;
            status = Some(parse_u16_lit(&value)?);
            Ok(())
        } else if meta.path.is_ident("code") {
            let value: Expr = meta.value()?.parse()?;
            code = Some(parse_str_lit(&value)?);
            Ok(())
        } else if meta.path.is_ident("outcome") {
            let value: Expr = meta.value()?.parse()?;
            let s = parse_str_lit(&value)?;
            match s.as_str() {
                "allowed" | "denied" | "error" => {}
                _ => {
                    return Err(
                        meta.error("outcome must be one of: \"allowed\", \"denied\", \"error\"")
                    )
                }
            }
            outcome = Some(s);
            Ok(())
        } else {
            Err(meta.error("unknown api key — supported: `status`, `code`, `outcome`"))
        }
    })?;

    let status =
        status.ok_or_else(|| Error::new_spanned(attr, "api attribute requires `status = N`"))?;
    let code = code.unwrap_or_else(|| to_snake_case(&variant_ident.to_string()));
    Ok(ApiAttrArgs {
        status,
        code,
        outcome,
    })
}

struct ApiAttrArgs {
    status: u16,
    code: String,
    outcome: Option<String>,
}

/// Convert a `PascalCase` identifier to `snake_case`. Used as the
/// default error `code` string when the variant doesn't supply one.
fn to_snake_case(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 4);
    for (i, c) in input.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.extend(c.to_lowercase());
    }
    out
}

fn parse_u16_lit(expr: &Expr) -> Result<u16> {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Int(int), ..
        }) => int.base10_parse::<u16>(),
        _ => Err(Error::new_spanned(
            expr,
            "expected an integer literal HTTP status code",
        )),
    }
}

fn parse_str_lit(expr: &Expr) -> Result<String> {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => Ok(s.value()),
        _ => Err(Error::new_spanned(expr, "expected a string literal")),
    }
}

// ---------------------------------------------------------------------------
// IntoResponse codegen
// ---------------------------------------------------------------------------

/// Generate `impl IntoResponse for Self`.
///
/// Moves the error enum directly into a typed
/// `ApiErrorBody<Self>` envelope. A `match &self` extracts the
/// variant's status, code, and name by reference, then `self` is moved
/// into the body. Tracing is dispatched at runtime based on the status
/// range.
fn generate_into_response(enum_name: &Ident, variants: &[ParsedVariant]) -> TokenStream {
    let match_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        let status = v.status;
        let code_str = &v.code;
        let variant_name = ident.to_string();
        let variant_name_lit = LitStr::new(&variant_name, proc_macro2::Span::call_site());
        let code_lit = LitStr::new(code_str, proc_macro2::Span::call_site());
        let status_lit = LitInt::new(&format!("{status}u16"), proc_macro2::Span::call_site());

        let pattern = match &v.shape {
            VariantShape::Unit => quote! { Self::#ident },
            VariantShape::SingleField(_) => quote! { Self::#ident(..) },
            VariantShape::Other => quote! { Self::#ident { .. } },
        };

        quote! {
            #pattern => (#status_lit, #code_lit, #variant_name_lit)
        }
    });

    // Capture the audit outcome before self is moved and attach it
    // to response extensions so AuditLayer can read it.
    let audit_capture = quote! {
        let __audit_outcome = {
            use ::doxa::__private::HasAuditOutcome as _;
            self_ref.audit_outcome()
        };
    };

    let audit_inject = quote! {
        let mut response = response;
        response.extensions_mut().insert(__audit_outcome);
    };

    quote! {
        #[automatically_derived]
        impl ::axum::response::IntoResponse for #enum_name {
            fn into_response(self) -> ::axum::response::Response {
                use ::axum::response::IntoResponse as _;

                // Capture the Display string before the borrow in the match.
                let detail: ::std::string::String = ::std::string::ToString::to_string(&self);

                // Borrow self to extract metadata, keeping self alive for
                // the move into the envelope.
                let self_ref = &self;
                let (status_u16, code_str, variant_name): (u16, &str, &str) = match self_ref {
                    #(#match_arms),*
                };

                // Capture audit outcome before self is consumed (when audit is enabled).
                #audit_capture

                // Structured tracing — runtime dispatch on status range.
                if status_u16 >= 500 {
                    ::doxa::__private::tracing::error!(
                        error_code = code_str,
                        error_kind = variant_name,
                        status = status_u16,
                        %detail,
                        "request failed",
                    );
                } else if status_u16 >= 400 {
                    ::doxa::__private::tracing::warn!(
                        error_code = code_str,
                        error_kind = variant_name,
                        status = status_u16,
                        %detail,
                        "request rejected",
                    );
                } else {
                    ::doxa::__private::tracing::debug!(
                        error_code = code_str,
                        error_kind = variant_name,
                        status = status_u16,
                        "response emitted",
                    );
                }

                // Move self into the typed envelope.
                let body = ::doxa::ApiErrorBody {
                    message: detail,
                    status: status_u16,
                    code: ::std::string::String::from(code_str),
                    error: self,
                };

                let status = ::axum::http::StatusCode::from_u16(status_u16)
                    .unwrap_or(::axum::http::StatusCode::INTERNAL_SERVER_ERROR);
                let response = (status, ::axum::Json(body)).into_response();

                // Attach outcome to response extensions (when audit is enabled).
                #audit_inject

                response
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IntoResponses codegen
// ---------------------------------------------------------------------------

/// Build the OpenAPI schema fragment for a single variant's `error`
/// field value, based on the externally-tagged serde representation.
fn variant_error_schema(v: &ParsedVariant) -> TokenStream {
    let variant_name = LitStr::new(&v.ident.to_string(), proc_macro2::Span::call_site());
    match &v.shape {
        VariantShape::Unit => {
            // Unit variant serializes as `"VariantName"` — a string constant.
            quote! {
                ::utoipa::openapi::ObjectBuilder::new()
                    .schema_type(::utoipa::openapi::schema::Type::String)
                    .enum_values(::std::option::Option::Some([
                        ::serde_json::json!(#variant_name),
                    ]))
            }
        }
        VariantShape::SingleField(inner_ty) => {
            // Newtype variant serializes as `{"VariantName": <inner>}`.
            // Resolve the inner type's schema via the trait system.
            quote! {
                ::utoipa::openapi::ObjectBuilder::new()
                    .property(
                        #variant_name,
                        <#inner_ty as ::utoipa::PartialSchema>::schema(),
                    )
                    .required(#variant_name)
            }
        }
        VariantShape::Other => {
            // Struct/multi-field variants — fall back to a generic object.
            // A future improvement could enumerate the fields here.
            quote! {
                ::utoipa::openapi::ObjectBuilder::new()
                    .schema_type(::utoipa::openapi::schema::Type::Object)
            }
        }
    }
}

/// Build the example JSON value for a single variant's `error` field,
/// matching the externally-tagged serde representation.
fn variant_example_error(v: &ParsedVariant) -> TokenStream {
    let variant_name_lit = LitStr::new(&v.ident.to_string(), proc_macro2::Span::call_site());
    match &v.shape {
        VariantShape::Unit => {
            quote! { ::serde_json::json!(#variant_name_lit) }
        }
        VariantShape::SingleField(_) => {
            let msg = format!("example {} message", v.ident);
            let msg_lit = LitStr::new(&msg, proc_macro2::Span::call_site());
            quote! { ::serde_json::json!({ #variant_name_lit: #msg_lit }) }
        }
        VariantShape::Other => {
            quote! { ::serde_json::json!({ #variant_name_lit: {} }) }
        }
    }
}

/// Generate `impl IntoResponses for Self`.
///
/// Builds a **separate envelope schema per status code** using
/// `ObjectBuilder`. For each status group the `code` property is
/// constrained to an enum of only the codes at that status, and the
/// `error` property is a `oneOf` of only the variants at that status.
fn generate_into_responses(enum_name: &Ident, variants: &[ParsedVariant]) -> TokenStream {
    // Group variants by status code, preserving declaration order within
    // each group.
    let mut grouped: BTreeMap<u16, Vec<&ParsedVariant>> = BTreeMap::new();
    for v in variants {
        grouped.entry(v.status).or_default().push(v);
    }

    let entries = grouped.iter().map(|(status, group)| {
        let status_str = LitStr::new(&status.to_string(), proc_macro2::Span::call_site());
        let status_lit = LitInt::new(&format!("{status}u16"), proc_macro2::Span::call_site());

        // Description: comma-separated list of codes.
        let description = if group.len() == 1 {
            group[0].code.clone()
        } else {
            let codes: Vec<_> = group.iter().map(|v| v.code.as_str()).collect();
            codes.join(", ")
        };
        let description_lit = LitStr::new(&description, proc_macro2::Span::call_site());

        // Code enum values for the `code` property.
        let code_enum_values = group.iter().map(|v| {
            let code_lit = LitStr::new(&v.code, proc_macro2::Span::call_site());
            quote! { ::serde_json::json!(#code_lit) }
        });

        // Per-variant error schemas for the `oneOf`.
        let error_schema_items: Vec<_> = group
            .iter()
            .map(|v| {
                let schema = variant_error_schema(v);
                quote! { .item(#schema) }
            })
            .collect();

        // Per-variant examples.
        let example_inserts = group.iter().map(|v| {
            let example_name = LitStr::new(&v.code, proc_macro2::Span::call_site());
            let summary = format!("{}: {}", v.ident, v.code);
            let summary_lit = LitStr::new(&summary, proc_macro2::Span::call_site());
            let code_lit = LitStr::new(&v.code, proc_macro2::Span::call_site());
            let variant_name_lit =
                LitStr::new(&v.ident.to_string(), proc_macro2::Span::call_site());
            let error_example = variant_example_error(v);

            quote! {
                {
                    let example_value = ::utoipa::openapi::example::ExampleBuilder::new()
                        .summary(#summary_lit)
                        .value(::std::option::Option::Some(::serde_json::json!({
                            "message": #variant_name_lit,
                            "status": #status_lit,
                            "code": #code_lit,
                            "error": #error_example,
                        })))
                        .build();
                    examples.insert(
                        ::std::string::String::from(#example_name),
                        ::utoipa::openapi::RefOr::T(example_value),
                    );
                }
            }
        });

        quote! {
            {
                let mut examples: ::std::collections::BTreeMap<
                    ::std::string::String,
                    ::utoipa::openapi::RefOr<::utoipa::openapi::example::Example>,
                > = ::std::collections::BTreeMap::new();
                #(#example_inserts)*

                // Build per-status error oneOf.
                let error_one_of = ::utoipa::openapi::OneOfBuilder::new()
                    #(#error_schema_items)*;

                // Build the full typed envelope for this status code.
                let envelope = ::utoipa::openapi::ObjectBuilder::new()
                    .property(
                        "message",
                        ::utoipa::openapi::ObjectBuilder::new()
                            .schema_type(::utoipa::openapi::schema::Type::String),
                    )
                    .required("message")
                    .property(
                        "status",
                        ::utoipa::openapi::ObjectBuilder::new()
                            .schema_type(::utoipa::openapi::schema::Type::Integer)
                            .enum_values(::std::option::Option::Some([
                                ::serde_json::json!(#status_lit),
                            ])),
                    )
                    .required("status")
                    .property(
                        "code",
                        ::utoipa::openapi::ObjectBuilder::new()
                            .schema_type(::utoipa::openapi::schema::Type::String)
                            .enum_values(::std::option::Option::Some([
                                #(#code_enum_values),*
                            ])),
                    )
                    .required("code")
                    .property("error", error_one_of)
                    .required("error");

                let content = ::utoipa::openapi::ContentBuilder::new()
                    .schema(::std::option::Option::Some(envelope))
                    .examples_from_iter(examples)
                    .build();

                let response = ::utoipa::openapi::ResponseBuilder::new()
                    .description(#description_lit)
                    .content("application/json", content)
                    .build();

                map.insert(
                    ::std::string::String::from(#status_str),
                    ::utoipa::openapi::RefOr::T(response),
                );
            }
        }
    });

    let _ = enum_name;
    quote! {
        #[automatically_derived]
        impl ::utoipa::IntoResponses for #enum_name {
            fn responses() -> ::std::collections::BTreeMap<
                ::std::string::String,
                ::utoipa::openapi::RefOr<::utoipa::openapi::response::Response>,
            > {
                let mut map: ::std::collections::BTreeMap<
                    ::std::string::String,
                    ::utoipa::openapi::RefOr<::utoipa::openapi::response::Response>,
                > = ::std::collections::BTreeMap::new();
                #(#entries)*
                map
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AuditOutcome codegen (feature = "audit")
// ---------------------------------------------------------------------------

/// Generate `impl HasAuditOutcome for Self`.
///
/// Each variant maps to its declared `outcome` attribute value. When
/// `outcome` is omitted, the variant defaults to `Error` —
/// conservative by default, opt-in to `"allowed"` or `"denied"`.
fn generate_audit_outcome(enum_name: &Ident, variants: &[ParsedVariant]) -> TokenStream {
    let match_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        let outcome_path = match v.outcome.as_deref() {
            Some("allowed") => quote! { ::doxa::__private::ResponseAuditOutcome::Allowed },
            Some("denied") => quote! { ::doxa::__private::ResponseAuditOutcome::Denied },
            // "error" or omitted — default to Error
            _ => quote! { ::doxa::__private::ResponseAuditOutcome::Error },
        };

        let pattern = match &v.shape {
            VariantShape::Unit => quote! { Self::#ident },
            VariantShape::SingleField(_) => quote! { Self::#ident(..) },
            VariantShape::Other => quote! { Self::#ident { .. } },
        };

        quote! { #pattern => #outcome_path }
    });

    quote! {
        #[automatically_derived]
        impl ::doxa::__private::HasAuditOutcome for #enum_name {
            fn audit_outcome(&self) -> ::doxa::__private::ResponseAuditOutcome {
                match self {
                    #(#match_arms),*
                }
            }
        }
    }
}
