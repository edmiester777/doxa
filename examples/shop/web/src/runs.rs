//! A page whose query string is one typed value.

use doxa::ui::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunStatus {
    Queued,
    Done,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RunFilter {
    pub status: Option<RunStatus>,
    #[serde(default)]
    pub page: u32,
}

/// A widget's runs, filtered and paged by `?status=…&page=…`.
#[page("/widgets/{name}/runs")]
pub fn RunsPage(name: String, #[query] filter: RunFilter) -> View {
    let next = RunsPage::route(&name).query(&RunFilter {
        page: filter.page + 1,
        ..filter.clone()
    });
    view! {
        <h1>{format!("{name} runs")}</h1>
        <p class="filter">{format!("{:?} page {}", filter.status, filter.page)}</p>
        <Link to={next}>"Next"</Link>
        <button
            class="done"
            on:click={|_| set_query_as(|f: &mut RunFilter| f.status = Some(RunStatus::Done))}
        >
            "Only done"
        </button>
    }
}
