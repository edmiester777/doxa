//! `view!`, `#[component]`, `#[page]`, `#[react]` and `#[start]` for doxa-ui. Use them through `doxa::ui`.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

mod binding;
mod component;
mod export;
mod form;
mod icons;
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

/// A plain JS module as typed Rust: `#[npm(module = "cronstrue")] extern "js" { fn … }`.
/// `#[npm(export = "…")]` on a `fn` names its export; `lazy` loads the module on first call.
#[proc_macro_attribute]
pub fn npm(args: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as syn::ItemForeignMod);
    binding::Args::parse(args.into())
        .and_then(|args| binding::expand(args, item))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// A React component used as a doxa one: `#[react(module = "…", export = "…", lazy?)]` on its props.
/// On an enum, each variant is the export of its name, given `props = …` (default `IconProps`).
#[proc_macro_attribute]
pub fn react(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as react::Args);
    match parse_macro_input!(item as syn::Item) {
        syn::Item::Struct(s) => react::expand(args, s),
        syn::Item::Enum(e) => icons::expand_react(args, e),
        other => Err(syn::Error::new_spanned(
            other,
            "`#[react]` goes on a props struct, or on an enum of components that share props",
        )),
    }
    .unwrap_or_else(syn::Error::into_compile_error)
    .into()
}

/// An enum of icons from SVG files: `#[icons(npm = "lucide-static", dir = "icons", case = "kebab")]`,
/// or `#[icons(dir = "./assets/icons")]` under the crate; `#[icons(file = "…")]` renames a variant's file.
#[proc_macro_attribute]
pub fn icons(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as icons::Args);
    let item = parse_macro_input!(item as syn::ItemEnum);
    icons::expand_icons(args, item)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// One `Field` per struct field, for `form(value).fields()`; `#[form(nested)]` for a struct
/// that derives `Form` too, `#[form(list)]` for a `Vec` of them.
#[proc_macro_derive(Form, attributes(form))]
pub fn derive_form(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as syn::DeriveInput);
    form::expand(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// A view shown alone in `doxa gallery`: `#[story] fn empty_list() -> View { … }`. Return
/// `(view, guard)` to keep a `push_scoped` layer for the story's life.
#[proc_macro_attribute]
pub fn story(_args: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = &item.sig.ident;
    let export = format!("__doxa_story_{name}");
    quote! {
        #item

        #[allow(unexpected_cfgs)]
        const _: () = {
            // Used, so a story isn't dead code outside the gallery.
            let _ = #name;
            #[cfg(all(doxa_gallery, target_arch = "wasm32"))]
            #[::doxa::ui::__private::wasm_bindgen::prelude::wasm_bindgen(js_name = #export, wasm_bindgen = ::doxa::ui::__private::wasm_bindgen)]
            pub fn __doxa_story(
                host: ::doxa::ui::__private::web_sys::Element,
            ) -> ::core::result::Result<::doxa::ui::__private::StoryHandle, ::doxa::ui::__private::wasm_bindgen::JsError> {
                ::doxa::ui::__private::mount_story(host, #name)
            }
        };
    }
    .into()
}

/// The wasm entry point: runs once the module loads, except in a `doxa build --lib` package or `doxa gallery`.
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
                if !::doxa::ui::__private::hosted() {
                    #name()
                }
            }

            // wasm-split hangs what only the main module calls off a function named `main`.
            #[unsafe(no_mangle)]
            pub extern "C" fn main() {}
        };
    }
    .into()
}
