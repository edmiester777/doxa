//! The native target gates, and `#[doxa::app]`, the native shell's entry.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Item, Result};

/// The cfg `#[doxa::app]` code compiles under: the shell binary, built with the crate's
/// `native` feature, never the page's wasm.
fn shell() -> TokenStream {
    quote!(all(
        doxa_native,
        not(target_arch = "wasm32"),
        feature = "native"
    ))
}

/// `#[doxa::native]` and its siblings: the item under `#[cfg(<cfg>)]`.
pub fn gate(cfg: &str, args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    if !args.is_empty() {
        return Err(syn::Error::new_spanned(
            args,
            format!("#[doxa::{}] takes no arguments", &cfg["doxa_".len()..]),
        ));
    }
    let item: Item = syn::parse2(item)?;
    let cfg = syn::Ident::new(cfg, proc_macro2::Span::call_site());
    Ok(quote!(#[cfg(#cfg)] #item))
}

/// `#[doxa::app]` on a `mod`: shell-only code. On a fn returning `doxa_native::App`: the entry.
pub fn app(args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    if !args.is_empty() {
        return Err(syn::Error::new_spanned(
            args,
            "#[doxa::app] takes no arguments",
        ));
    }
    let shell = shell();
    match syn::parse2::<Item>(item)? {
        Item::Mod(m) => Ok(quote!(#[cfg(#shell)] #m)),
        Item::Fn(f) => {
            let sig = &f.sig;
            if sig.asyncness.is_some() || !sig.inputs.is_empty() || !sig.generics.params.is_empty()
            {
                return Err(syn::Error::new_spanned(
                    sig,
                    "#[doxa::app] goes on `fn app() -> doxa_native::App`",
                ));
            }
            let name = &sig.ident;
            Ok(quote! {
                #[cfg(#shell)]
                #f

                #[cfg(#shell)]
                #[doc(hidden)]
                #[cfg_attr(doxa_mobile, ::tauri::mobile_entry_point)]
                pub fn __app_run() {
                    #name().__run(
                        ::tauri::generate_context!(),
                        ::core::env!("DOXA_NATIVE_CONFIG"),
                    )
                }

                #[doc(hidden)]
                pub fn __app_main() {
                    #[cfg(#shell)]
                    __app_run();
                    #[cfg(not(#shell))]
                    {
                        ::std::eprintln!(
                            "error: this binary is the native app; build it with `doxa build --desktop`"
                        );
                        ::std::process::exit(1);
                    }
                }
            })
        }
        other => Err(syn::Error::new_spanned(
            other,
            "#[doxa::app] goes on the app's `fn app() -> doxa_native::App`, or on a `mod` of shell-only code",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gate_wraps_the_item_in_its_cfg() {
        let out = gate(
            "doxa_ios",
            quote!(),
            quote!(
                fn f() {}
            ),
        )
        .unwrap();
        assert_eq!(
            out.to_string(),
            quote!(
                #[cfg(doxa_ios)]
                fn f() {}
            )
            .to_string()
        );
        assert!(gate(
            "doxa_ios",
            quote!(x),
            quote!(
                fn f() {}
            )
        )
        .unwrap_err()
        .to_string()
        .contains("#[doxa::ios] takes no arguments"));
    }

    #[test]
    fn app_on_a_mod_is_shell_only_and_on_a_fn_adds_the_entry() {
        let m = app(
            quote!(),
            quote!(
                mod shell {}
            ),
        )
        .unwrap()
        .to_string();
        assert!(m.contains("not (target_arch = \"wasm32\")"), "{m}");
        let f = app(
            quote!(),
            quote!(
                fn app() -> doxa_native::App {
                    todo!()
                }
            ),
        )
        .unwrap()
        .to_string();
        assert!(f.contains("__app_run") && f.contains("__app_main"), "{f}");
        assert!(f.contains("mobile_entry_point"), "{f}");
        assert!(app(
            quote!(),
            quote!(
                async fn app() {}
            )
        )
        .is_err());
        assert!(app(
            quote!(),
            quote!(
                struct S;
            )
        )
        .is_err());
    }
}
