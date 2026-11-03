//! A button that passes whatever its tag carries on to the `<button>`.

use doxa::ui::prelude::*;

#[component]
pub fn Button(children: View, #[attrs] rest: Attrs) -> View {
    let class = match rest.class() {
        Some(c) => format!("btn {c}"),
        None => "btn".to_owned(),
    };
    view! { <button type="button" class={class} {..rest}>{children}</button> }
}
