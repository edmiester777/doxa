//! Components a React app embeds, through `doxa build --lib`.

use doxa::ui::prelude::*;
use widgets_client::widgets::*;

use crate::Count;

/// The widgets whose names contain `contains`; `on_open` gets the name picked.
#[component(export)]
pub async fn WidgetPicker(contains: Option<String>, on_open: Callback<String>) -> Result<View> {
    let widgets = list_widgets(Filter { contains }).await?;
    let picks = state(0u32);
    Ok(view! {
        <div class="picker">
            <Count total={widgets.len()} on_pick={move |_: bool| picks.update(|n| *n += 1)}/>
            <p class="picks">{picks.get()}</p>
            {widgets.iter().map(|w| {
                let (name, open) = (w.name.clone(), on_open.clone());
                view! {
                    <button key={w.id} class="open" on:click={move |_| open.call(name.clone())}>
                        {&w.name}
                    </button>
                }
            }).collect::<View>()}
        </div>
    })
}

/// A widget's name as a heading.
#[component(export)]
pub async fn WidgetTitle(name: String, #[prop(default = 1)] level: u8) -> Result<View> {
    let w = get_widget(&WidgetKey { name }).await?;
    Ok(view! { <p class="title" data-level={level.to_string()}>{&w.name}</p> })
}
