//! Reading a type by its last path segment, never resolved, so `Option<T>` and `std::option::Option<T>` match alike.

use syn::{GenericArgument, PathArguments, Type, TypePath};

pub(crate) fn last_ident(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(TypePath { path, .. }) => path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    }
}

/// The type arguments of the last path segment, lifetimes and consts skipped.
pub(crate) fn type_args(ty: &Type) -> Vec<&Type> {
    let Type::Path(TypePath { path, .. }) = ty else {
        return Vec::new();
    };
    let Some(PathArguments::AngleBracketed(args)) = path.segments.last().map(|s| &s.arguments)
    else {
        return Vec::new();
    };
    args.args
        .iter()
        .filter_map(|a| match a {
            GenericArgument::Type(t) => Some(t),
            _ => None,
        })
        .collect()
}

pub(crate) fn first_type_arg(ty: &Type) -> Option<&Type> {
    type_args(ty).into_iter().next()
}

/// `T` when `ty` is `name<T, …>`.
pub(crate) fn inner_of<'a>(ty: &'a Type, name: &str) -> Option<&'a Type> {
    (last_ident(ty)? == name)
        .then(|| first_type_arg(ty))
        .flatten()
}
