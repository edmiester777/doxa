//! Function props: `impl Fn(A, B) -> R` in a signature, and the setters a `Callback` gets.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{GenericArgument, PathArguments, ReturnType, Type, TypeParamBound};

use crate::ty::inner_of;

/// A `Callback<dyn Fn(A, B) -> R>`, read from its syntax.
pub(crate) struct Sig {
    pub inputs: Vec<Type>,
    pub output: ReturnType,
    /// `R` when it is `Fn(A) -> LocalBoxFuture<'static, R>`, what `impl AsyncFn(A) -> R` becomes.
    pub future_of: Option<Type>,
}

impl Sig {
    fn returns_unit(&self) -> bool {
        match &self.output {
            ReturnType::Default => true,
            ReturnType::Type(_, t) => matches!(&**t, Type::Tuple(t) if t.elems.is_empty()),
        }
    }

    fn owned_inputs(&self) -> bool {
        !self
            .inputs
            .iter()
            .any(|t| quote!(#t).to_string().contains('&'))
    }
}

/// The `Fn`-family bound of `impl Fn(…)` or `dyn Fn(…)`: its name and arguments.
fn fn_bound(
    bounds: &syn::punctuated::Punctuated<TypeParamBound, syn::Token![+]>,
) -> Option<(String, &syn::ParenthesizedGenericArguments)> {
    bounds.iter().find_map(|b| {
        let TypeParamBound::Trait(t) = b else {
            return None;
        };
        let last = t.path.segments.last()?;
        let PathArguments::Parenthesized(args) = &last.arguments else {
            return None;
        };
        Some((last.ident.to_string(), args))
    })
}

/// `impl Fn(…)` as the `Callback` it is, here or inside an `Option`.
pub(crate) fn desugar(ty: &mut Type) -> syn::Result<()> {
    if let Type::Path(p) = ty {
        if let Some(last) = p.path.segments.last_mut().filter(|s| s.ident == "Option") {
            if let PathArguments::AngleBracketed(a) = &mut last.arguments {
                if let Some(GenericArgument::Type(t)) = a.args.first_mut() {
                    desugar(t)?;
                }
            }
        }
        return Ok(());
    }
    let Type::ImplTrait(i) = &*ty else {
        return Ok(());
    };
    let Some((name, args)) = fn_bound(&i.bounds) else {
        return Err(syn::Error::new(
            i.span(),
            "a prop's `impl` is a function, `impl Fn(A, B) -> R` or `impl AsyncFn(A) -> R`",
        ));
    };
    let inputs = args.inputs.iter();
    let output = &args.output;
    *ty = match name.as_str() {
        "Fn" => syn::parse_quote_spanned!(i.span()=>
            ::doxa::ui::Callback<dyn Fn(#(#inputs),*) #output>
        ),
        "AsyncFn" => {
            if let Some(t) = args.inputs.iter().find(|t| quote!(#t).to_string().contains('&')) {
                return Err(syn::Error::new(
                    t.span(),
                    "an `impl AsyncFn` prop's arguments are owned: its future outlives the call",
                ));
            }
            let value = match output {
                ReturnType::Default => quote!(()),
                ReturnType::Type(_, t) => quote!(#t),
            };
            syn::parse_quote_spanned!(i.span()=>
                ::doxa::ui::Callback<
                    dyn Fn(#(#inputs),*) -> ::doxa::ui::__private::LocalBoxFuture<'static, #value>
                >
            )
        }
        other => {
            return Err(syn::Error::new(
                i.span(),
                format!(
                    "a prop can be called many times, so it is `impl Fn` or `impl AsyncFn`, not `impl {other}`"
                ),
            ))
        }
    };
    Ok(())
}

/// The signature of a `Callback<…>`; a bare `Callback` takes nothing.
pub(crate) fn signature(ty: &Type) -> Option<Sig> {
    let Type::Path(p) = ty else { return None };
    let last = p.path.segments.last().filter(|s| s.ident == "Callback")?;
    let args = match &last.arguments {
        PathArguments::None => {
            return Some(Sig {
                inputs: Vec::new(),
                output: ReturnType::Default,
                future_of: None,
            })
        }
        PathArguments::AngleBracketed(a) => a,
        PathArguments::Parenthesized(_) => return None,
    };
    let Some(GenericArgument::Type(Type::TraitObject(object))) = args.args.first() else {
        return None;
    };
    let (name, f) = fn_bound(&object.bounds)?;
    if name != "Fn" {
        return None;
    }
    let future_of = match &f.output {
        ReturnType::Type(_, t) => inner_of_future(t),
        ReturnType::Default => None,
    };
    Some(Sig {
        inputs: f.inputs.iter().cloned().collect(),
        output: f.output.clone(),
        future_of,
    })
}

fn inner_of_future(ty: &Type) -> Option<Type> {
    inner_of(ty, "LocalBoxFuture").cloned()
}

/// The setters `view!` picks for a literal closure, so the prop's signature types its parameters.
/// Each is `(name, generics, argument, the Callback it builds)`.
pub(crate) fn closure_setters(
    prop: &syn::Ident,
    ty: &Type,
    sig: &Sig,
) -> Vec<(syn::Ident, TokenStream, TokenStream, TokenStream)> {
    let unraw = syn::ext::IdentExt::unraw(prop);
    let names = |prefix: &str| format_ident!("__{}_{}", prefix, unraw, span = prop.span());
    let inputs = &sig.inputs;
    let vars: Vec<_> = (0..inputs.len())
        .map(|i| format_ident!("__a{}", i))
        .collect();
    let params = quote!(#(#vars: #inputs),*);
    let new = |body: TokenStream| quote!(<#ty>::from_rc(::std::rc::Rc::new(#body)));
    let mut out = Vec::new();

    if let Some(value) = &sig.future_of {
        let boxed = |call: TokenStream| {
            new(quote! {{
                let __f = ::std::rc::Rc::new(__f);
                move |#params| -> ::doxa::ui::__private::LocalBoxFuture<'static, #value> {
                    let __f = __f.clone();
                    ::std::boxed::Box::pin(async move { #call })
                }
            }})
        };
        let all = boxed(quote!(__f(#(#vars),*).await));
        let none = boxed(quote! {{ #(let _ = #vars;)* __f().await }});
        for prefix in ["fn", "afn"] {
            out.push((
                names(prefix),
                quote!(),
                quote!(__f: impl AsyncFn(#(#inputs),*) -> #value + 'static),
                all.clone(),
            ));
            out.push((
                names(&format!("{prefix}0")),
                quote!(),
                quote!(__f: impl AsyncFn() -> #value + 'static),
                none.clone(),
            ));
        }
        return out;
    }

    let output = &sig.output;
    out.push((
        names("fn"),
        quote!(),
        quote!(__f: impl Fn(#(#inputs),*) #output + 'static),
        new(quote!(__f)),
    ));
    out.push((
        names("fn0"),
        quote!(),
        quote!(__f: impl Fn() #output + 'static),
        new(quote!(move |#params| { #(let _ = #vars;)* __f() })),
    ));
    if sig.returns_unit() && sig.owned_inputs() {
        let spawning = |call: TokenStream| {
            new(quote! {{
                let __f = ::std::rc::Rc::new(__f);
                let __owner = ::doxa::ui::__private::owner();
                move |#params| {
                    let __f = __f.clone();
                    __owner.spawn(async move { #call });
                }
            }})
        };
        out.push((
            names("afn"),
            quote!(<__R: ::doxa::ui::Outcome>),
            quote!(__f: impl AsyncFn(#(#inputs),*) -> __R + 'static),
            spawning(quote!(__f(#(#vars),*).await)),
        ));
        out.push((
            names("afn0"),
            quote!(<__R: ::doxa::ui::Outcome>),
            quote!(__f: impl AsyncFn() -> __R + 'static),
            spawning(quote! {{ #(let _ = #vars;)* __f().await }}),
        ));
    }
    out
}
