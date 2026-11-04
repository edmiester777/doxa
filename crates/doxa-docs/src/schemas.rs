//! Component names two Rust types claim, which one document can only hold one of.

use std::borrow::Cow;
use std::collections::BTreeMap;

/// One `#[dto]` type's schema name, registered wherever its crate is linked.
pub struct Named {
    /// The component name, `<T as ToSchema>::name`.
    pub name: fn() -> Cow<'static, str>,
    /// The Rust type, `type_name::<T>`.
    pub ty: fn() -> &'static str,
}

inventory::collect!(Named);

/// Each component name more than one linked `#[dto]` type claims, with those types.
pub fn duplicate_schemas() -> Vec<(String, Vec<&'static str>)> {
    let mut by_name: BTreeMap<String, Vec<&'static str>> = BTreeMap::new();
    for n in inventory::iter::<Named> {
        let types = by_name.entry((n.name)().into_owned()).or_default();
        let ty = (n.ty)();
        if !types.contains(&ty) {
            types.push(ty);
        }
    }
    by_name
        .into_iter()
        .filter(|(_, types)| types.len() > 1)
        .map(|(name, mut types)| {
            types.sort_unstable();
            (name, types)
        })
        .collect()
}
