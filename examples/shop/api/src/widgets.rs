//! What the shop sells.

doxa::prelude!();

route_key!(pub WidgetKey { name: String });

/// What a caller may do with widgets.
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

/// A widget. `id` never changes; `name` is how routes address it.
#[dto]
#[entity(key = WidgetKey, actions = WidgetAction)]
#[derive(Identity)]
#[identity(id = id, key = WidgetKey { name })]
pub struct Widget {
    pub id: u32,
    pub name: String,
}

/// A name for a widget; the server and the form check the same rule.
#[dto]
#[derive(garde::Validate)]
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

/// One widget, by name.
#[get("/api/widgets/{name}")]
pub async fn get_widget(widget: Grant<Widget>) -> Json<Widget>;

/// Every widget the caller may see.
#[get("/api/widgets")]
pub async fn list_widgets(_: Grant<Many<Widget>>, filter: Query<Filter>) -> Json<Vec<Widget>>;

/// Rename a widget.
#[patch("/api/widgets/{name}")]
pub async fn rename_widget(
    widget: Grant<Widget>,
    rename: Valid<Json<Rename>>,
) -> Result<Json<Widget>, WidgetError>;

/// Suggest a name for a new widget. Anyone may, so nothing guards it.
#[post("/api/suggestions")]
pub async fn suggest_name(suggestion: Json<Rename>) -> StatusCode;

/// A widget's label, as a file to save.
#[get("/api/widgets/{name}/label")]
pub async fn widget_label(widget: Grant<Widget>) -> Attachment;

/// Upload a widget's photo; answers its size in bytes.
#[put("/api/widgets/{name}/photo")]
pub async fn upload_photo(widget: Grant<Widget>, photo: Bytes) -> Json<usize>;

/// Upload files; answers each field as `name=size`.
#[post("/api/uploads")]
pub async fn upload_files(form: Multipart) -> Json<Vec<String>>;

/// What happens to a widget, as it happens.
#[get("/api/widgets/{name}/events")]
pub async fn widget_events(widget: Grant<Widget>) -> SseStream<WidgetEvent>;
