//! `#[doxa::main]`: the binary's `fn main`, with `start` reserved for doxa to call.

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{FnArg, ItemFn, Path, Token};

struct Args {
    cli: Option<Path>,
    init: Option<Path>,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut args = Args {
            cli: None,
            init: None,
        };
        if !input.is_empty() && !(input.peek(syn::Ident) && input.peek2(Token![=])) {
            args.cli = Some(input.parse()?);
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        if !input.is_empty() {
            let key: Ident = input.parse()?;
            if key != "init" {
                return Err(syn::Error::new(
                    key.span(),
                    "expected `init = path::to::fn`",
                ));
            }
            input.parse::<Token![=]>()?;
            args.init = Some(input.parse()?);
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        if !input.is_empty() {
            return Err(input.error("expected `#[doxa::main]`, `#[doxa::main(Cli)]` or `init = f`"));
        }
        Ok(args)
    }
}

pub fn expand(args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let args: Args = syn::parse2(args)?;
    let mut f: ItemFn = syn::parse2(item)?;
    let sig = &f.sig;
    if sig.asyncness.is_none() {
        return Err(syn::Error::new_spanned(
            sig.fn_token,
            "#[doxa::main] goes on an `async fn`",
        ));
    }
    if !sig.generics.params.is_empty() || sig.generics.where_clause.is_some() {
        return Err(syn::Error::new_spanned(
            &sig.generics,
            "#[doxa::main] doesn't take generics",
        ));
    }
    if let Some(FnArg::Receiver(r)) = sig.inputs.first() {
        return Err(syn::Error::new_spanned(
            r,
            "#[doxa::main] goes on a free fn",
        ));
    }
    let init = match &args.init {
        Some(p) => quote!(::core::option::Option::Some(#p as fn())),
        None => quote!(::core::option::Option::None),
    };
    let pkg = quote! {
        ::doxa::boot::__Package {
            bin: match ::core::option_env!("CARGO_BIN_NAME") {
                ::core::option::Option::Some(b) => b,
                ::core::option::Option::None => ::core::env!("CARGO_PKG_NAME"),
            },
            version: ::core::env!("CARGO_PKG_VERSION"),
            about: ::core::env!("CARGO_PKG_DESCRIPTION"),
        }
    };
    match args.cli {
        None => {
            if sig.ident != "start" {
                return Err(syn::Error::new_spanned(
                    &sig.ident,
                    "without a Cli, #[doxa::main] goes on `async fn start`; \
                     to put it on `main`, pass the app's parser: #[doxa::main(Cli)]",
                ));
            }
            let start = &sig.ident;
            let call = match sig.inputs.len() {
                0 => quote!(|_, _| #start()),
                1 => quote!(|_, stop| #start(stop)),
                _ => {
                    return Err(syn::Error::new_spanned(
                        &sig.inputs,
                        "`start` takes nothing, or `stop: doxa::boot::Stopping`",
                    ))
                }
            };
            Ok(quote! {
                #f

                fn main() -> ::std::process::ExitCode {
                    ::doxa::boot::__run::<::doxa::boot::__NoCli, _, _, _, _>(
                        #pkg, #init, #call, |_| async {},
                    )
                }
            })
        }
        Some(cli) => {
            if sig.ident == "start" {
                return Err(syn::Error::new_spanned(
                    &sig.ident,
                    "`start` is reserved: doxa calls it for the `start` subcommand; \
                     put #[doxa::main(Cli)] on `async fn main(cli: Cli)`",
                ));
            }
            if sig.inputs.len() != 1 {
                return Err(syn::Error::new_spanned(
                    &sig.inputs,
                    "#[doxa::main(Cli)] goes on a fn taking the parsed Cli: `async fn main(cli: Cli)`",
                ));
            }
            // The attribute's span, so a missing `start` is reported at `#[doxa::main(Cli)]`.
            let start = Ident::new("start", cli.span());
            f.sig.ident = format_ident!("__doxa_main");
            let main = &f.sig.ident;
            Ok(quote! {
                #f

                fn main() -> ::std::process::ExitCode {
                    ::doxa::boot::__run::<#cli, _, _, _, _>(
                        #pkg, #init, |cli, stop| #start(cli, stop), |cli| #main(cli),
                    )
                }
            })
        }
    }
}
