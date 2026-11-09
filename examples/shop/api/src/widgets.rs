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

/// Every widget route, behind the caller's role.
#[doxa::service(layers = caller)]
pub struct Widgets;

/// One widget, by name.
#[get("/api/widgets/{name}")]
pub async fn get_widget(widget: Grant<Widget>) -> Json<Widget> {
    Json(widget.into_inner().into())
}

/// Every widget the caller may see.
#[get("/api/widgets")]
pub async fn list_widgets(
    _: Grant<Many<Widget>>,
    State(catalog): State<Catalog>,
    Query(filter): Query<Filter>,
) -> Json<Vec<Widget>> {
    Json(catalog.list(filter.contains.as_deref()))
}

/// Rename a widget.
#[patch("/api/widgets/{name}")]
pub async fn rename_widget(
    widget: Grant<Widget>,
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
pub async fn widget_label(widget: Grant<Widget>) -> Attachment {
    let name = widget.into_inner().name;
    Attachment::new(format!("{name}\n"))
        .content_type("text/plain")
        .filename(format!("{name} label.txt"))
}

/// Upload a widget's photo; answers its size in bytes.
#[put("/api/widgets/{name}/photo")]
pub async fn upload_photo(_widget: Grant<Widget>, photo: Bytes) -> Json<usize> {
    Json(photo.len())
}

/// Upload files; answers each field as `name=size`.
#[post("/api/uploads")]
pub async fn upload_files(form: Multipart) -> Json<Vec<String>> {
    Json(field_sizes(form).await)
}

/// What happens to a widget, as it happens.
#[get("/api/widgets/{name}/events")]
pub async fn widget_events(
    widget: Grant<Widget>,
) -> SseStream<
    WidgetEvent,
    impl futures::Stream<Item = Result<WidgetEvent, std::convert::Infallible>>,
> {
    use futures::stream;
    let name = widget.into_inner().name;
    SseStream::new(stream::iter([
        Ok(WidgetEvent::Renamed { name }),
        Ok(WidgetEvent::Deleted),
    ]))
}
