//! The widget routes, written once. The server runs them; the client calls them.

doxa::prelude!();

#[server]
use crate::store::{AppGrants, Catalog};
#[server]
use futures::stream::{self, Stream};
#[server]
use std::convert::Infallible;

/// A widget. `id` never changes; `name` is how routes address it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema, PolicyResource, Identity)]
#[resource(entity_type = "Widget")]
#[identity(id = id, key = WidgetKey { name })]
pub struct Widget {
    #[resource(id)]
    pub id: u32,
    #[resource(attr)]
    pub name: String,
}

route_key!(pub WidgetKey { name: String });

/// The new name for a widget.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Rename {
    pub name: String,
}

/// Narrows a listing.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema, IntoParams)]
pub struct Filter {
    pub contains: Option<String>,
}

/// What can go wrong renaming a widget.
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize, ToSchema, ApiError)]
pub enum WidgetError {
    #[error("the name `{0}` is taken")]
    #[api(status = 409, code = "name_taken")]
    NameTaken(String),
}

/// Something that happened to a widget.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, SseEvent)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum WidgetEvent {
    Renamed { name: String },
    Deleted,
}

#[derive(Debug, Clone, Copy, Actions)]
#[actions(resource = "Widget", prefix = "widgets")]
pub enum WidgetAction {
    /// View widgets.
    #[action(verb = get)]
    Read,
    /// Rename widgets.
    #[action(verb = patch)]
    Update,
}

#[asset(row = Widget, key = WidgetKey, profile = AppGrants, actions = WidgetAction, list = tenant)]
pub struct WidgetByName;

/// One widget, by name.
#[get("/api/widgets/{name}")]
pub async fn get_widget(widget: Granted<WidgetByName>) -> Json<Widget> {
    Json(widget.into_inner())
}

/// Every widget the caller may see.
#[get("/api/widgets")]
pub async fn list_widgets(
    _scope: Granted<Many<WidgetByName>>,
    State(catalog): State<Catalog>,
    Query(filter): Query<Filter>,
) -> Json<Vec<Widget>> {
    Json(catalog.list(filter.contains.as_deref()))
}

/// Rename a widget.
#[patch("/api/widgets/{name}")]
pub async fn rename_widget(
    widget: Granted<WidgetByName>,
    State(catalog): State<Catalog>,
    Json(rename): Json<Rename>,
) -> Result<Json<Widget>, WidgetError> {
    catalog.rename(widget.id, &rename.name).map(Json)
}

/// What happens to a widget, as it happens.
#[get("/api/widgets/{name}/events")]
pub async fn widget_events(
    widget: Granted<WidgetByName>,
) -> SseStream<WidgetEvent, impl Stream<Item = Result<WidgetEvent, Infallible>>> {
    let name = widget.into_inner().name;
    SseStream::new(stream::iter([
        Ok(WidgetEvent::Renamed { name }),
        Ok(WidgetEvent::Deleted),
    ]))
}
