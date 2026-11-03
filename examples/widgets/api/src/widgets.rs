//! The widget routes, written once. The server runs them; the client calls them.

doxa::prelude!();

#[server]
use crate::store::{AppGrants, Caller, Catalog};
#[server]
use axum::{body::Bytes, extract::Multipart};
#[server]
use doxa::Valid;
#[server]
use futures::stream::{self, Stream};
#[server]
use std::convert::Infallible;
#[server]
use utoipa::ToResponse;

/// A widget. `id` never changes; `name` is how routes address it.
#[dto]
#[derive(PolicyResource, Identity)]
#[resource(entity_type = "Widget")]
#[identity(id = id, key = WidgetKey { name })]
pub struct Widget {
    #[resource(id)]
    pub id: u32,
    #[resource(attr)]
    pub name: String,
}

route_key!(pub WidgetKey { name: String });

/// The new name for a widget; the server and the form check the same rule.
#[dto]
#[derive(garde::Validate, ToResponse)]
#[response(description = "A name for a widget")]
pub struct Rename {
    #[garde(length(min = 1, max = 40))]
    pub name: String,
}

/// Narrows a listing.
#[dto(query)]
#[derive(Default)]
pub struct Filter {
    pub contains: Option<String>,
}

/// What can go wrong renaming a widget.
#[dto]
#[derive(thiserror::Error, ApiError)]
pub enum WidgetError {
    #[error("the name `{0}` is taken")]
    #[api(status = 409, code = "name_taken")]
    NameTaken(String),
}

/// Something that happened to a widget.
#[dto]
#[derive(SseEvent)]
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
    Valid(Json(rename)): Valid<Json<Rename>>,
) -> Result<Json<Widget>, WidgetError> {
    catalog.rename(widget.id, &rename.name).map(Json)
}

/// Suggest a name for a new widget. Anyone may, so nothing guards it.
#[post("/api/suggestions")]
pub async fn suggest_name(
    State(catalog): State<Catalog>,
    #[server] Caller(who): Caller,
    Json(suggestion): Json<Rename>,
) -> StatusCode {
    catalog.suggest(format!("{} from {who}", suggestion.name));
    StatusCode::ACCEPTED
}

/// A widget's label, as a file to save.
#[get("/api/widgets/{name}/label")]
pub async fn widget_label(widget: Granted<WidgetByName>) -> Attachment {
    let name = widget.into_inner().name;
    Attachment::new(format!("{name}\n"))
        .content_type("text/plain")
        .filename(format!("{name} label.txt"))
}

/// Upload a widget's photo; answers its size in bytes.
#[put("/api/widgets/{name}/photo")]
pub async fn upload_photo(_widget: Granted<WidgetByName>, photo: Bytes) -> Json<usize> {
    Json(photo.len())
}

/// Upload files; answers each field as `name=size`.
#[post("/api/uploads")]
pub async fn upload_files(mut form: Multipart) -> Json<Vec<String>> {
    let mut fields = Vec::new();
    while let Ok(Some(field)) = form.next_field().await {
        let name = field.name().unwrap_or_default().to_owned();
        let file = field.file_name().map(str::to_owned);
        let size = field.bytes().await.map_or(0, |b| b.len());
        fields.push(match file {
            Some(f) => format!("{name}:{f}={size}"),
            None => format!("{name}={size}"),
        });
    }
    Json(fields)
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
