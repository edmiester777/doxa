//! `#[derive(Validator)]`: a validating wrapper's extractor and OpenAPI impls, from its
//! `Validates` impls.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, GenericParam};

pub fn expand(input: TokenStream) -> syn::Result<TokenStream> {
    let input: DeriveInput = syn::parse2(input)?;
    let name = &input.ident;
    let shape_error = || {
        syn::Error::new_spanned(
            name,
            "`Validator` derives on a wrapper with one type parameter: `struct Valid<E>(pub E);`",
        )
    };
    let one_field = matches!(&input.data, Data::Struct(s) if matches!(&s.fields, Fields::Unnamed(f) if f.unnamed.len() == 1));
    let params: Vec<_> = input.generics.params.iter().collect();
    let [GenericParam::Type(_)] = params.as_slice() else {
        return Err(shape_error());
    };
    if !one_field {
        return Err(shape_error());
    }
    let ax = quote!(::doxa::__private::axum);
    let body = |extractor: TokenStream| {
        quote! {
            impl<__S, __T> #ax::extract::FromRequest<__S> for #name<#extractor<__T>>
            where
                __S: ::core::marker::Send + ::core::marker::Sync,
                #extractor<__T>: #ax::extract::FromRequest<__S>,
                Self: ::doxa::wire::Validates<Value = __T>,
            {
                type Rejection = ::doxa::ValidRejection<
                    <#extractor<__T> as #ax::extract::FromRequest<__S>>::Rejection,
                >;

                async fn from_request(
                    req: #ax::extract::Request,
                    state: &__S,
                ) -> ::core::result::Result<Self, Self::Rejection> {
                    let inner = <#extractor<__T> as #ax::extract::FromRequest<__S>>::from_request(req, state)
                        .await
                        .map_err(::doxa::ValidRejection::Inner)?;
                    <Self as ::doxa::wire::Validates>::check(&inner.0)
                        .map_err(::doxa::ValidRejection::Invalid)?;
                    ::core::result::Result::Ok(#name(inner))
                }
            }
        }
    };
    let parts = |extractor: TokenStream| {
        quote! {
            impl<__S, __T> #ax::extract::FromRequestParts<__S> for #name<#extractor<__T>>
            where
                __S: ::core::marker::Send + ::core::marker::Sync,
                #extractor<__T>: #ax::extract::FromRequestParts<__S>,
                Self: ::doxa::wire::Validates<Value = __T>,
            {
                type Rejection = ::doxa::ValidRejection<
                    <#extractor<__T> as #ax::extract::FromRequestParts<__S>>::Rejection,
                >;

                async fn from_request_parts(
                    parts: &mut #ax::http::request::Parts,
                    state: &__S,
                ) -> ::core::result::Result<Self, Self::Rejection> {
                    let inner = <#extractor<__T> as #ax::extract::FromRequestParts<__S>>::from_request_parts(parts, state)
                        .await
                        .map_err(::doxa::ValidRejection::Inner)?;
                    <Self as ::doxa::wire::Validates>::check(&inner.0)
                        .map_err(::doxa::ValidRejection::Invalid)?;
                    ::core::result::Result::Ok(#name(inner))
                }
            }
        }
    };
    let optional_json = quote! {
        impl<__S, __T> #ax::extract::FromRequest<__S> for #name<::core::option::Option<#ax::Json<__T>>>
        where
            __S: ::core::marker::Send + ::core::marker::Sync,
            #ax::Json<__T>: #ax::extract::OptionalFromRequest<__S>,
            Self: ::doxa::wire::Validates<Value = ::core::option::Option<__T>>,
        {
            type Rejection = ::doxa::ValidRejection<
                <#ax::Json<__T> as #ax::extract::OptionalFromRequest<__S>>::Rejection,
            >;

            async fn from_request(
                req: #ax::extract::Request,
                state: &__S,
            ) -> ::core::result::Result<Self, Self::Rejection> {
                let inner = <#ax::Json<__T> as #ax::extract::OptionalFromRequest<__S>>::from_request(req, state)
                    .await
                    .map_err(::doxa::ValidRejection::Inner)?;
                let value = inner.map(|j| j.0);
                <Self as ::doxa::wire::Validates>::check(&value)
                    .map_err(::doxa::ValidRejection::Invalid)?;
                ::core::result::Result::Ok(#name(value.map(#ax::Json)))
            }
        }
    };
    let json = body(quote!(#ax::Json));
    let form = body(quote!(#ax::extract::Form));
    let query = parts(quote!(#ax::extract::Query));
    let op = quote!(::doxa::__private::utoipa::openapi::path::Operation);

    let server = quote! {
        #json
        #optional_json
        #form
        #query

        impl<__E: ::doxa::DocQueryParams> ::doxa::DocQueryParams for #name<__E> {
            fn describe(op: &mut #op) {
                __E::describe(op);
                ::doxa::__private::document_invalid(op);
            }
        }

        impl<__E: ::doxa::DocPathParams> ::doxa::DocPathParams for #name<__E> {
            fn describe(op: &mut #op, names: &[&'static str]) {
                __E::describe(op, names)
            }
        }

        impl<__E: ::doxa::DocPathScalar> ::doxa::DocPathScalar for #name<__E> {
            fn describe_scalar(op: &mut #op, names: &[&'static str]) {
                __E::describe_scalar(op, names)
            }
        }

        impl<__E: ::doxa::DocHeaderParams> ::doxa::DocHeaderParams for #name<__E> {
            fn describe(op: &mut #op) {
                __E::describe(op)
            }
        }

        impl<__E: ::doxa::DocRequestBody> ::doxa::DocRequestBody for #name<__E> {
            fn describe(op: &mut #op) {
                __E::describe(op);
                ::doxa::__private::document_invalid(op);
            }
        }
    };
    Ok(doxa_macro_support::tag(
        doxa_macro_support::Side::Server,
        server,
    ))
}
