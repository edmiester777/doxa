//! `#[component(export)]`: a wasm export mounting the component, and its props' TypeScript
//! types in a `doxa_exports` custom section that `doxa build --lib` reads.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{GenericArgument, PathArguments, Type};

use crate::component::Parsed;

/// `on_close` → `onClose`.
pub(crate) fn camel(name: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in name.chars() {
        if c == '_' {
            upper = !out.is_empty();
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// The last path segment of `ty` and its type arguments.
fn segment(ty: &Type) -> Option<(String, Vec<&Type>)> {
    let Type::Path(p) = ty else { return None };
    let last = p.path.segments.last()?;
    let args = match &last.arguments {
        PathArguments::AngleBracketed(a) => a
            .args
            .iter()
            .filter_map(|a| match a {
                GenericArgument::Type(t) => Some(t),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    Some((last.ident.to_string(), args))
}

/// `ty` in TypeScript, from its syntax; a type it doesn't know is `unknown`.
pub(crate) fn ts(ty: &Type) -> String {
    match ty {
        Type::Reference(r) => return ts(&r.elem),
        Type::Tuple(t) if t.elems.is_empty() => return "void".into(),
        Type::Tuple(t) => {
            let items: Vec<_> = t.elems.iter().map(ts).collect();
            return format!("[{}]", items.join(", "));
        }
        Type::Slice(s) => return format!("{}[]", wrap(&ts(&s.elem))),
        Type::Array(a) => return format!("{}[]", wrap(&ts(&a.elem))),
        _ => {}
    }
    if let Some(sig) = crate::callback::signature(ty) {
        return match sig.inputs.as_slice() {
            [] => "() => void".into(),
            [one] => format!("(value: {}) => void", ts(one)),
            many => {
                let args: Vec<_> = many
                    .iter()
                    .enumerate()
                    .map(|(i, t)| format!("arg{i}: {}", ts(t)))
                    .collect();
                format!("({}) => void", args.join(", "))
            }
        };
    }
    let Some((name, args)) = segment(ty) else {
        return "unknown".into();
    };
    let arg = |i: usize| args.get(i).map_or("unknown".to_owned(), |t| ts(t));
    match name.as_str() {
        "String" | "str" | "char" | "Cow" | "Rc" | "Arc" | "Box" if !args.is_empty() => arg(0),
        "String" | "str" | "char" => "string".into(),
        "bool" => "boolean".into(),
        "u8" | "u16" | "u32" | "u64" | "usize" | "i8" | "i16" | "i32" | "i64" | "isize" | "f32"
        | "f64" => "number".into(),
        "Vec" | "VecDeque" | "HashSet" | "BTreeSet" => format!("{}[]", wrap(&arg(0))),
        "HashMap" | "BTreeMap" => format!("Record<string, {}>", arg(1)),
        "Option" => format!("{} | null", arg(0)),
        _ => "unknown".into(),
    }
}

fn wrap(t: &str) -> String {
    if t.contains(' ') {
        format!("({t})")
    } else {
        t.to_owned()
    }
}

pub(crate) fn expand(parsed: &Parsed) -> syn::Result<TokenStream> {
    let name = &parsed.item.sig.ident;
    let props_ty = format_ident!("{}Props", name);
    let export = format!("__doxa_export_{name}");
    let mut fields = Vec::new();
    let mut described = Vec::new();
    for p in &parsed.props {
        let n = &p.name;
        if segment(&p.ty).is_some_and(|(s, _)| s == "View") {
            return Err(syn::Error::new(
                n.span(),
                "an exported component's props come from JS, which can't pass a `View`",
            ));
        }
        let js = camel(&n.to_string());
        let ty = &p.ty;
        let (value, optional) = if let Some(sig) = crate::callback::signature(ty) {
            if !matches!(sig.output, syn::ReturnType::Default) {
                return Err(syn::Error::new(
                    n.span(),
                    "an exported component's callback returns nothing: JS answers asynchronously",
                ));
            }
            let inputs = &sig.inputs;
            (
                quote! { ::doxa::ui::__private::callback::<dyn Fn(#(#inputs),*)>(calls, props, #js)? },
                true,
            )
        } else if p.optional {
            (
                quote! { ::doxa::ui::__private::prop::<#ty>(props, #js)? },
                true,
            )
        } else if let Some(default) = &p.default {
            (
                quote! {
                    match ::doxa::ui::__private::prop::<::core::option::Option<#ty>>(props, #js)? {
                        ::core::option::Option::Some(v) => v,
                        ::core::option::Option::None => #default,
                    }
                },
                true,
            )
        } else {
            (
                quote! { ::doxa::ui::__private::prop::<#ty>(props, #js)? },
                false,
            )
        };
        fields.push(quote! { #n: #value });
        let ts = if p.optional {
            segment(ty)
                .and_then(|(_, a)| a.first().map(|t| ts(t)))
                .unwrap_or_else(|| "unknown".into())
        } else {
            ts(ty)
        };
        described.push(serde_json::json!({ "name": js, "ts": ts, "optional": optional }));
    }
    let mut meta = serde_json::json!({
        "component": name.to_string(),
        "export": export,
        "props": described,
    })
    .to_string();
    meta.push('\n');
    let bytes = syn::LitByteStr::new(meta.as_bytes(), name.span());
    let len = meta.len();
    Ok(quote! {
        #[cfg(target_arch = "wasm32")]
        const _: () = {
            use ::doxa::ui::__private::wasm_bindgen;

            #[wasm_bindgen::prelude::wasm_bindgen(js_name = #export, wasm_bindgen = ::doxa::ui::__private::wasm_bindgen)]
            pub fn __doxa_export(
                host: ::doxa::ui::__private::web_sys::Element,
                props: wasm_bindgen::JsValue,
            ) -> ::core::result::Result<::doxa::ui::__private::ExportHandle, wasm_bindgen::JsError> {
                ::doxa::ui::__private::mount_export::<#name>(host, &props, |calls, props| {
                    let _ = calls;
                    ::core::result::Result::Ok(#props_ty { #(#fields),* })
                })
            }

            #[used]
            #[unsafe(link_section = "doxa_exports")]
            static __DOXA_EXPORT: [u8; #len] = *#bytes;
        };
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts_of(src: &str) -> String {
        ts(&syn::parse_str(src).unwrap())
    }

    #[test]
    fn prop_types_map_to_typescript() {
        assert_eq!(ts_of("String"), "string");
        assert_eq!(ts_of("&'static str"), "string");
        assert_eq!(ts_of("u32"), "number");
        assert_eq!(ts_of("Vec<Option<String>>"), "(string | null)[]");
        assert_eq!(ts_of("BTreeMap<String, f64>"), "Record<string, number>");
        assert_eq!(ts_of("Callback"), "() => void");
        assert_eq!(ts_of("Callback<dyn Fn()>"), "() => void");
        assert_eq!(ts_of("Callback<dyn Fn(u8)>"), "(value: number) => void");
        assert_eq!(
            ts_of("Callback<dyn Fn(String, u8)>"),
            "(arg0: string, arg1: number) => void"
        );
        assert_eq!(ts_of("Rc<str>"), "string");
        assert_eq!(ts_of("Order"), "unknown");
    }

    #[test]
    fn snake_props_are_camel_in_js() {
        assert_eq!(camel("on_close"), "onClose");
        assert_eq!(camel("thread"), "thread");
        assert_eq!(camel("max_row_count"), "maxRowCount");
    }
}
