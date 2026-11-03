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
    /// The `#[attrs]` prop, collecting what the tag passes that isn't a prop.
    pub rest: Option<Ident>,
    /// A page's `#[query]` prop, parsed from the whole query string.
    pub query: Option<Ident>,
}

#[derive(Default)]
pub(crate) struct Options {
    pub memo: bool,
    /// Render from its own wasm module, split off by `doxa build`.
    pub lazy: bool,
    /// Mountable by a foreign React host, through `doxa build --lib`.
    pub export: bool,
}

impl syn::parse::Parse for Options {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut o = Options::default();
        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            match ident.to_string().as_str() {
                "memo" => o.memo = true,
                "export" => o.export = true,
                other => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!("unknown option `{other}`; expected `memo` or `export`"),
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
    if let Some(p) = item
        .sig
        .generics
        .params
        .iter()
        .find(|p| !matches!(p, syn::GenericParam::Type(_)))
    {
        return Err(syn::Error::new(
            p.span(),
            "a component's generic parameters are types; lifetimes and consts aren't supported",
        ));
    }
    let mut props = Vec::new();
    let mut rest = None;
    let mut query = None;
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
            if attr.path().is_ident("attrs") {
                let is_attrs = matches!(&*pt.ty, Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Attrs"));
                if !is_attrs {
                    return Err(syn::Error::new(
                        pt.ty.span(),
                        "an `#[attrs]` prop is a `doxa::ui::Attrs`",
                    ));
                }
                if rest.replace(name.clone()).is_some() {
                    return Err(syn::Error::new(
                        attr.span(),
                        "a component takes one `#[attrs]` prop",
                    ));
                }
                default = Some(quote!(::core::default::Default::default()));
            } else if attr.path().is_ident("query") {
                if query.replace(name.clone()).is_some() {
                    return Err(syn::Error::new(
                        attr.span(),
                        "a page takes one `#[query]` prop; it holds the whole query string",
                    ));
                }
            } else if attr.path().is_ident("prop") {
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
    Ok(Parsed {
        item,
        props,
        rest,
        query,
    })
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
    let generics = &parsed.item.sig.generics;
    if opts.export && !generics.params.is_empty() {
        return syn::Error::new(
            generics.span(),
            "an exported component can't be generic: its host passes props as JSON to one type",
        )
        .into_compile_error();
    }
    if let (true, Some(r)) = (opts.export, &parsed.rest) {
        return syn::Error::new(
            r.span(),
            "an exported component's props come from its host as JSON, so it can't take `#[attrs]`",
        )
        .into_compile_error();
    }
    let exported = if opts.export {
        match crate::export::expand(parsed) {
            Ok(t) => t,
            Err(e) => return e.into_compile_error(),
        }
    } else {
        quote!()
    };
    let Parsed {
        item, props, rest, ..
    } = parsed;
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
                ::core::option::Option::Some(|a, b| a.downcast_ref::<Self::Props>() == b.downcast_ref::<Self::Props>());
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
    let builder = builder(vis, name, &props_ty, props, generics, rest.as_ref());
    let (impl_g, ty_g, where_c) = generics.split_for_impl();
    let unit = if generics.params.is_empty() {
        quote!(#vis struct #name;)
    } else {
        let tys = generics.type_params().map(|t| &t.ident);
        quote!(#vis struct #name #generics (::core::marker::PhantomData<fn() -> (#(#tys,)*)>) #where_c;)
    };

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
        // A hot-patched build stays one module, so `doxa dev` loads lazy pages eagerly.
        // The lint allowance only reaches a cfg from an enclosing item.
        let split = quote! {
            #[cfg(target_arch = "wasm32")]
            #[doc(hidden)]
            #[allow(non_snake_case, unexpected_cfgs)]
            mod #module {
                #[cfg(not(doxa_hot))]
                use super::*;
                #[cfg(not(doxa_hot))]
                use ::doxa::ui::__private::wasm_split;

                #[cfg(not(doxa_hot))]
                pub(super) fn render(props: #props_ty) -> ::doxa::ui::RenderFuture { #render }

                #[cfg(not(doxa_hot))]
                pub(super) static LOADER: wasm_split::LazyLoader<#props_ty, ::doxa::ui::RenderFuture> =
                    wasm_split::lazy_loader!(extern #abi fn render(props: #props_ty) -> ::doxa::ui::RenderFuture);
            }
        };
        let render = quote! {
            #[cfg(all(target_arch = "wasm32", not(doxa_hot)))]
            return ::doxa::ui::RenderFuture::new(async move {
                if !#module::LOADER.load().await {
                    return ::core::result::Result::Err(::doxa::ui::Thrown::msg(concat!("couldn't load the code for ", #name_str)));
                }
                match #module::LOADER.call(props) {
                    ::core::result::Result::Ok(view) => view.await,
                    ::core::result::Result::Err(e) => ::core::result::Result::Err(::doxa::ui::Thrown::msg(e.to_string())),
                }
            });
            #[cfg(any(not(target_arch = "wasm32"), doxa_hot))]
            { #render }
        };
        (split, render)
    } else {
        (quote!(), render)
    };

    quote! {
        #(#docs)*
        #unit

        #[doc = concat!("Props of [`", #name_str, "`].")]
        #[derive(Clone)]
        #derive_eq
        #vis struct #props_ty #generics #where_c { #(#fields),* }

        #builder

        impl #impl_g ::doxa::ui::Component for #name #ty_g #where_c {
            type Props = #props_ty #ty_g;
            const NAME: &'static str = #name_str;
            #same_props

            #[allow(unexpected_cfgs)]
            fn render(props: Self::Props) -> ::doxa::ui::RenderFuture {
                #render
            }
        }

        impl #impl_g ::doxa::ui::ComponentProps for #props_ty #ty_g #where_c {
            type Of = #name #ty_g;
        }

        #split
        #exported
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
    generics: &syn::Generics,
    rest: Option<&Ident>,
) -> TokenStream {
    let builder = format_ident!("{}Builder", name);
    let names: Vec<_> = props.iter().map(|p| &p.name).collect();
    let required: Vec<_> = props.iter().filter(|p| p.default.is_none()).collect();
    let params: Vec<_> = (0..required.len())
        .map(|i| format_ident!("__P{}", i))
        .collect();
    let tys: Vec<Ident> = generics.type_params().map(|t| t.ident.clone()).collect();
    let (impl_g, ty_g, where_c) = generics.split_for_impl();
    let mut with_state = generics.clone();
    with_state.params.extend(
        params
            .iter()
            .map(|p| -> syn::GenericParam { syn::parse_quote!(#p) }),
    );
    let (state_impl, state_ty, state_where) = with_state.split_for_impl();
    let mut finished = with_state.clone();
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
    finished.make_where_clause().predicates.extend(
        params
            .iter()
            .zip(&needs)
            .map(|(p, n)| -> syn::WherePredicate { syn::parse_quote!(#p: #n) }),
    );
    let (finished_impl, _, finished_where) = finished.split_for_impl();
    // A prop over a component's own parameter takes exactly its type, so the tag infers it.
    let mentions_param = |t: &Type| {
        fn walk(ts: TokenStream, tys: &[Ident]) -> bool {
            ts.into_iter().any(|tt| match tt {
                proc_macro2::TokenTree::Ident(i) => tys.contains(&i),
                proc_macro2::TokenTree::Group(g) => walk(g.stream(), tys),
                _ => false,
            })
        }
        walk(quote!(#t), &tys)
    };

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
        } else if mentions_param(t) {
            (quote!(value: #t), quote!(value))
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
            pub fn #n(self, #arg) -> #builder<#(#tys,)* #(#out_params),*> {
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

    let rest = rest.map(|r| {
        quote! {
            impl #state_impl ::doxa::ui::__private::RestAttrs for #builder #state_ty #state_where {
                fn __rest(&mut self) -> &mut ::doxa::ui::Attrs {
                    self.#r.get_or_insert_with(::core::default::Default::default)
                }
            }
        }
    });

    quote! {
        #rest

        #(
            #[doc(hidden)]
            #[allow(non_camel_case_types)]
            #[diagnostic::on_unimplemented(message = #messages, label = #labels)]
            #vis trait #needs {}
            impl #needs for ::doxa::ui::Set {}
        )*

        #[doc = concat!("Builds [`", stringify!(#props_ty), "`].")]
        #vis struct #builder #with_state #state_where {
            #(#builder_fields,)*
            _set: ::core::marker::PhantomData<(fn() -> (#(#tys,)*), #(#params,)*)>,
        }

        impl #impl_g #name #ty_g #where_c {
            /// Start building its props.
            #vis fn props() -> #builder<#(#tys,)* #(#unset),*> {
                #builder { #(#names: ::core::option::Option::None,)* _set: ::core::marker::PhantomData }
            }
        }

        #[allow(dead_code)]
        impl #state_impl #builder #state_ty #state_where {
            #(#setters)*
        }

        impl #finished_impl #builder #state_ty #finished_where {
            /// Finish; every required prop must be given.
            #vis fn build(self) -> #props_ty #ty_g {
                #props_ty { #(#build_fields),* }
            }
        }
    }
}
