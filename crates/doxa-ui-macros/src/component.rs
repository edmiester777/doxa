//! `#[component]`: a function becomes a unit struct, a props struct and a typestate builder.

use proc_macro2::TokenStream;
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{FnArg, Ident, ItemFn, Pat, Type};

pub(crate) struct Prop {
    pub name: Ident,
    pub ty: Type,
    pub default: Option<TokenStream>,
    pub optional: bool,
}

pub(crate) struct Parsed {
    pub item: ItemFn,
    pub props: Vec<Prop>,
}

#[derive(Default)]
pub(crate) struct Options {
    pub memo: bool,
    /// Render from its own wasm module, split off by `doxa build`.
    pub lazy: bool,
}

impl syn::parse::Parse for Options {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut o = Options::default();
        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            match ident.to_string().as_str() {
                "memo" => o.memo = true,
                other => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!("unknown option `{other}`; expected `memo`"),
                    ))
                }
            }
            if !input.is_empty() {
                input.parse::<syn::Token![,]>()?;
            }
        }
        Ok(o)
    }
}

pub(crate) fn parse(mut item: ItemFn) -> syn::Result<Parsed> {
    if !item.sig.generics.params.is_empty() {
        return Err(syn::Error::new(
            item.sig.generics.span(),
            "components can't be generic",
        ));
    }
    let mut props = Vec::new();
    for arg in &mut item.sig.inputs {
        let FnArg::Typed(pt) = arg else {
            return Err(syn::Error::new(
                arg.span(),
                "a component is a free function, not a method",
            ));
        };
        let Pat::Ident(pi) = &*pt.pat else {
            return Err(syn::Error::new(
                pt.pat.span(),
                "name each prop: `name: Type`",
            ));
        };
        let name = pi.ident.clone();
        if name == "key" {
            return Err(syn::Error::new(
                name.span(),
                "`key` is reserved for list identity; rename the prop",
            ));
        }
        let mut default = None;
        let mut kept = Vec::new();
        for attr in pt.attrs.drain(..) {
            if attr.path().is_ident("prop") {
                attr.parse_nested_meta(|m| {
                    if m.path.is_ident("default") {
                        default = Some(match m.value() {
                            Ok(v) => {
                                let e: syn::Expr = v.parse()?;
                                quote!(#e)
                            }
                            Err(_) => quote!(::core::default::Default::default()),
                        });
                        Ok(())
                    } else {
                        Err(m.error("expected `default` or `default = …`"))
                    }
                })?;
            } else {
                kept.push(attr);
            }
        }
        pt.attrs = kept;
        let ty = (*pt.ty).clone();
        let optional = is_option(&ty);
        if default.is_none() && (optional || name == "children") {
            default = Some(quote!(::core::default::Default::default()));
        }
        props.push(Prop {
            name,
            ty,
            default,
            optional,
        });
    }
    no_spawn(&item.block)?;
    Ok(Parsed { item, props })
}

/// A render runs again on every change, so a task it spawns would be spawned again each time.
/// Closures and nested items aren't the render, so they may spawn.
fn no_spawn(body: &syn::Block) -> syn::Result<()> {
    use syn::visit::Visit;

    struct Find(Option<proc_macro2::Span>);
    impl<'a> Visit<'a> for Find {
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            if let syn::Expr::Path(p) = &*call.func {
                if p.path.segments.last().is_some_and(|s| s.ident == "spawn") {
                    self.0.get_or_insert(call.func.span());
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_closure(&mut self, _: &'a syn::ExprClosure) {}
        fn visit_item(&mut self, _: &'a syn::Item) {}
    }

    let mut find = Find(None);
    find.visit_block(body);
    match find.0 {
        Some(span) => Err(syn::Error::new(
            span,
            "use `effect` (or `action`) instead of spawning in a render",
        )),
        None => Ok(()),
    }
}

fn is_option(ty: &Type) -> bool {
    matches!(ty, Type::Path(p) if p.qself.is_none() && p.path.segments.last().is_some_and(|s| s.ident == "Option"))
}

pub(crate) fn expand(opts: Options, parsed: &Parsed) -> TokenStream {
    let Parsed { item, props } = parsed;
    let vis = &item.vis;
    let name = &item.sig.ident;
    let name_str = name.to_string();
    let props_ty = format_ident!("{}Props", name);
    let docs: Vec<_> = item
        .attrs
        .iter()
        .filter(|a| a.path().is_ident("doc"))
        .collect();
    let others: Vec<_> = item
        .attrs
        .iter()
        .filter(|a| !a.path().is_ident("doc"))
        .collect();

    let fields = props.iter().map(|p| {
        let (n, t) = (&p.name, &p.ty);
        quote! { pub #n: #t }
    });
    let names: Vec<_> = props.iter().map(|p| &p.name).collect();

    let same_props = if opts.memo {
        quote! {
            const SAME_PROPS: ::core::option::Option<fn(&::std::rc::Rc<dyn ::core::any::Any>, &::std::rc::Rc<dyn ::core::any::Any>) -> bool> =
                ::core::option::Option::Some(|a, b| a.downcast_ref::<#props_ty>() == b.downcast_ref::<#props_ty>());
        }
    } else {
        quote!()
    };
    let derive_eq = if opts.memo {
        quote!(#[derive(PartialEq)])
    } else {
        quote!()
    };

    let inner_sig = {
        let mut s = item.sig.clone();
        s.ident = format_ident!("__render");
        s
    };
    let body = &item.block;
    let call = if item.sig.asyncness.is_some() {
        quote! {
            ::doxa::ui::RenderFuture::new(async move {
                ::doxa::ui::IntoRender::into_render(__render(#(#names),*).await)
            })
        }
    } else {
        quote! { ::doxa::ui::RenderFuture::ready(::doxa::ui::IntoRender::into_render(__render(#(#names),*))) }
    };
    let builder = builder(vis, name, &props_ty, props);

    let render = quote! {
        #(#others)*
        #[allow(non_snake_case, clippy::too_many_arguments)]
        #inner_sig #body
        let #props_ty { #(#names),* } = props;
        #call
    };
    let (split, render) = if opts.lazy {
        let module = lazy_mod(name);
        let abi = syn::LitStr::new(&snake(&name_str), name.span());
        let split = quote! {
            #[cfg(target_arch = "wasm32")]
            #[doc(hidden)]
            #[allow(non_snake_case)]
            mod #module {
                use super::*;
                use ::doxa::ui::__private::wasm_split;

                pub(super) fn render(props: #props_ty) -> ::doxa::ui::RenderFuture { #render }

                pub(super) static LOADER: wasm_split::LazyLoader<#props_ty, ::doxa::ui::RenderFuture> =
                    wasm_split::lazy_loader!(extern #abi fn render(props: #props_ty) -> ::doxa::ui::RenderFuture);
            }
        };
        let render = quote! {
            #[cfg(target_arch = "wasm32")]
            return ::doxa::ui::RenderFuture::new(async move {
                if !#module::LOADER.load().await {
                    return ::core::result::Result::Err(::doxa::ui::Thrown::msg(concat!("couldn't load the code for ", #name_str)));
                }
                match #module::LOADER.call(props) {
                    ::core::result::Result::Ok(view) => view.await,
                    ::core::result::Result::Err(e) => ::core::result::Result::Err(::doxa::ui::Thrown::msg(e.to_string())),
                }
            });
            #[cfg(not(target_arch = "wasm32"))]
            { #render }
        };
        (split, render)
    } else {
        (quote!(), render)
    };

    quote! {
        #(#docs)*
        #vis struct #name;

        #[doc = concat!("Props of [`", #name_str, "`].")]
        #[derive(Clone)]
        #derive_eq
        #vis struct #props_ty { #(#fields),* }

        #builder

        impl ::doxa::ui::Component for #name {
            type Props = #props_ty;
            const NAME: &'static str = #name_str;
            #same_props

            fn render(props: #props_ty) -> ::doxa::ui::RenderFuture {
                #render
            }
        }

        #split
    }
}

/// The module holding a lazy component's split point.
pub(crate) fn lazy_mod(name: &Ident) -> Ident {
    format_ident!("__doxa_lazy_{}", name)
}

/// `ReportsPage` → `reports_page`, the split module's name.
fn snake(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.extend(c.to_lowercase());
    }
    out
}

/// The typestate builder for `props_ty`: `build()` needs every prop without a default.
pub(crate) fn builder(
    vis: &syn::Visibility,
    name: &Ident,
    props_ty: &Ident,
    props: &[Prop],
) -> TokenStream {
    let builder = format_ident!("{}Builder", name);
    let names: Vec<_> = props.iter().map(|p| &p.name).collect();
    let required: Vec<_> = props.iter().filter(|p| p.default.is_none()).collect();
    let params: Vec<_> = (0..required.len())
        .map(|i| format_ident!("__P{}", i))
        .collect();
    let needs: Vec<_> = required
        .iter()
        .map(|p| format_ident!("{}_needs_{}", name, p.name))
        .collect();
    let messages = required
        .iter()
        .map(|p| format!("`<{name}>` is missing the `{}` prop", p.name));
    let labels = required
        .iter()
        .map(|p| format!("add `{}={{{{…}}}}` to the tag", p.name));
    let unset = required.iter().map(|_| quote!(::doxa::ui::Unset));

    let setters = props.iter().map(|p| {
        let (n, t) = (&p.name, &p.ty);
        let pos = required.iter().position(|r| r.name == p.name);
        let out_params = params.iter().enumerate().map(|(i, g)| {
            if Some(i) == pos {
                quote!(::doxa::ui::Set)
            } else {
                quote!(#g)
            }
        });
        let (arg, convert) = if n == "children" {
            (
                quote!(value: ::doxa::ui::View),
                quote!(::doxa::ui::__private::FromChildren::from_children(value)),
            )
        } else {
            (
                quote!(value: impl ::core::convert::Into<#t>),
                quote!(::core::convert::Into::into(value)),
            )
        };
        let moves = names.iter().map(|m| {
            if *m == n {
                quote!(#m: ::core::option::Option::Some(#convert))
            } else {
                quote!(#m: self.#m)
            }
        });
        quote_spanned! { n.span() =>
            #[allow(missing_docs)]
            pub fn #n(self, #arg) -> #builder<#(#out_params),*> {
                #builder { #(#moves,)* _set: ::core::marker::PhantomData }
            }
        }
    });

    let build_fields = props.iter().map(|p| {
        let n = &p.name;
        match &p.default {
            Some(d) => quote!(#n: self.#n.unwrap_or_else(|| #d)),
            None => quote!(#n: self.#n.expect("checked by the builder's type")),
        }
    });
    let builder_fields = props.iter().map(|p| {
        let (n, t) = (&p.name, &p.ty);
        quote!(#n: ::core::option::Option<#t>)
    });

    quote! {
        #(
            #[doc(hidden)]
            #[allow(non_camel_case_types)]
            #[diagnostic::on_unimplemented(message = #messages, label = #labels)]
            #vis trait #needs {}
            impl #needs for ::doxa::ui::Set {}
        )*

        #[doc = concat!("Builds [`", stringify!(#props_ty), "`].")]
        #vis struct #builder<#(#params),*> {
            #(#builder_fields,)*
            _set: ::core::marker::PhantomData<(#(#params,)*)>,
        }

        impl #name {
            /// Start building its props.
            #vis fn props() -> #builder<#(#unset),*> {
                #builder { #(#names: ::core::option::Option::None,)* _set: ::core::marker::PhantomData }
            }
        }

        #[allow(dead_code)]
        impl<#(#params),*> #builder<#(#params),*> {
            #(#setters)*
        }

        impl<#(#params),*> #builder<#(#params),*> {
            /// Finish; every required prop must be given.
            #vis fn build(self) -> #props_ty where #(#params: #needs),* {
                #props_ty { #(#build_fields),* }
            }
        }
    }
}
