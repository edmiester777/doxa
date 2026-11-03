//! A button that passes whatever its tag carries on to the `<button>`.

use doxa::ui::prelude::*;

#[component]
pub fn Button(children: View, #[attrs] rest: Attrs) -> View {
    // A `px-1` on the tag replaces `px-3` rather than fighting it.
    let class = doxa::tailwind::cn!["btn px-3", rest.class()];
    view! { <button type="button" class={class} {..rest}>{children}</button> }
}
