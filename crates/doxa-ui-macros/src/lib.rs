//! `view!`, `#[component]`, `#[page]`, `#[react]` and `#[start]` for doxa-ui. Use them through `doxa::ui`.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

mod component;
mod form;
mod npm;
mod page;
mod react;
mod view;

/// Markup: `view! { <p class="x">{&name}</p> <Row widget={w}/> }`.
#[proc_macro]
pub fn view(input: TokenStream) -> TokenStream {
    view::expand(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// A component: a function from props to `View` or `Result<View>`, sync or async.
#[proc_macro_attribute]
pub fn component(args: TokenStream, item: TokenStream) -> TokenStream {
    let opts = parse_macro_input!(args as component::Options);
    let item = parse_macro_input!(item as ItemFn);
    match component::parse(item) {
        Ok(parsed) => component::expand(opts, &parsed).into(),
        Err(e) => e.into_compile_error().into(),
    }
}

/// A component reached at a path: `#[page("/widgets/{name}", load = |p| get_widget(&p.name))]`.
/// With `lazy`, `doxa build` splits its code into a wasm module fetched on hover or navigation.
#[proc_macro_attribute]
pub fn page(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as page::Args);
    let item = parse_macro_input!(item as ItemFn);
    component::parse(item)
        .and_then(|parsed| page::expand(args, &parsed))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// A React component used as a doxa one: `#[react(module = "…", export = "…", lazy?)]` on its props.
#[proc_macro_attribute]
pub fn react(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as react::Args);
    let item = parse_macro_input!(item as syn::ItemStruct);
    react::expand(args, item)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// One `Field` per struct field, for `form(value).fields()`.
#[proc_macro_derive(Form)]
pub fn derive_form(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as syn::DeriveInput);
    form::expand(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// The wasm entry point: runs once the module loads.
#[proc_macro_attribute]
pub fn start(_args: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = &item.sig.ident;
    quote! {
        #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
        #item

        #[cfg(target_arch = "wasm32")]
        const _: () = {
            use ::doxa::ui::__private::wasm_bindgen;
            #[wasm_bindgen::prelude::wasm_bindgen(start, wasm_bindgen = ::doxa::ui::__private::wasm_bindgen)]
            fn __doxa_start() {
                #name()
            }

            // wasm-split hangs what only the main module calls off a function named `main`.
            #[unsafe(no_mangle)]
            pub extern "C" fn main() {}
        };
    }
    .into()
}
