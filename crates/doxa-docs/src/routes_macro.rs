//! [`routes!`](crate::routes) — drop-in replacement for
//! [`utoipa_axum::routes!`] that additionally collects schemas
//! referenced by handler-argument types.
//!
//! See the `utoipa_axum::routes!` expansion for the primary
//! plumbing; we wrap it to also extend the collected schemas with
//! those referenced by each handler's argument types through its
//! generated [`ApidocHandlerSchemas`](crate::ApidocHandlerSchemas)
//! impl. Caller-facing syntax is unchanged.

/// Wraps [`utoipa_axum::routes!`] and augments the schemas vector
/// with everything each handler's argument types reference.
///
/// Accepts either `ident` handlers (`routes!(list_models)`) or
/// qualified paths (`routes!(pets::get_pet)`), matching the upstream
/// macro's caller surface.
#[macro_export]
macro_rules! routes {
    // Top-level entry: utoipa-axum captures handlers as `:path` and
    // the capture becomes opaque to subsequent :ident matchers, so
    // we parse handler paths here as `:tt` sequences that we can
    // walk token-by-token in the recursion below. The list is
    // forwarded verbatim to `utoipa_axum::routes!`.
    //
    // The grammar is: a handler is one or more `ident` tokens
    // separated by `::`. Handlers are separated by `,`.
    ($($handler_seg:ident $(:: $handler_rest:ident)*),+ $(,)?) => {{
        let mut __routes_result = $crate::__private::utoipa_axum_routes!(
            $($handler_seg $(:: $handler_rest)*),+
        );
        $(
            $crate::routes!(
                @collect __routes_result,
                prefix: [],
                rest: $handler_seg $(:: $handler_rest)*
            );
        )+
        __routes_result
    }};

    // Muncher: accumulate prefix tokens while more `::` segments
    // follow, then paste the final `__path_<last>` into the
    // prefix-qualified path.
    (@collect $r:ident, prefix: [$($prefix:tt)*], rest: $head:ident :: $($tail:tt)+) => {
        $crate::routes!(
            @collect $r,
            prefix: [$($prefix)* $head ::],
            rest: $($tail)+
        )
    };
    (@collect $r:ident, prefix: [$($prefix:tt)*], rest: $last:ident) => {
        $crate::__private::paste::paste! {
            <$($prefix)* [<__path_ $last>]
                as $crate::ApidocHandlerSchemas>::collect(&mut $r.0);
            <$($prefix)* [<__path_ $last>]
                as $crate::ApidocHandlerOps>::augment(&mut $r.1);
        }
    };
}
