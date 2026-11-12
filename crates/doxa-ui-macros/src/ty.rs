//! Reading a prop's type by its last path segment, so `Option<T>` and `std::option::Option<T>` match alike.

use syn::{GenericArgument, PathArguments, Type};

/// Whether `ty`'s last path segment is `name`.
pub(crate) fn is_named(ty: &Type, name: &str) -> bool {
    matches!(ty, Type::Path(p) if p.qself.is_none() && p.path.segments.last().is_some_and(|s| s.ident == name))
}

/// The first type argument of `ty` when it is `name<…>`.
pub(crate) fn inner_of<'a>(ty: &'a Type, name: &str) -> Option<&'a Type> {
    let Type::Path(p) = ty else { return None };
    let last = p.path.segments.last().filter(|s| s.ident == name)?;
    let PathArguments::AngleBracketed(a) = &last.arguments else {
        return None;
    };
    a.args.iter().find_map(|a| match a {
        GenericArgument::Type(t) => Some(t),
        _ => None,
    })
}
