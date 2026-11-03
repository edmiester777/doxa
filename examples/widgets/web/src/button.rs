//! A button that passes whatever its tag carries on to the `<button>`.

use doxa::ui::prelude::*;

#[component]
pub fn Button(children: View, #[attrs] rest: Attrs) -> View {
    let class = classes!["btn", rest.class()];
    view! { <button type="button" class={class} {..rest}>{children}</button> }
}
