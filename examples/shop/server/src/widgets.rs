//! Where widgets live, and the routes that serve them.

use std::convert::Infallible;
use std::sync::{Arc, RwLock};

use axum::body::Bytes;
use axum::extract::{Multipart, Query, State};
use axum::http::StatusCode;
use axum::Json;
use futures::stream::{self, Stream};

use doxa::auth::{CapabilityContext, FromState, GrantProfile, Granted, Many};
use doxa::policy::{Fetch, FetchByKey, FetchSubset};
use doxa::{asset, implements, Attachment, PolicyResource, SseStream, Valid};

use shop_api::widgets::{
    Filter, Rename, Widget, WidgetAction, WidgetError, WidgetEvent, WidgetKey,
};

/// Every widget route, behind the caller's role.
#[doxa::service(layers = crate::caller)]
pub struct Widgets;

/// A widget as the server stores it.
#[derive(Debug, Clone, serde::Serialize, PolicyResource)]
#[resource(entity_type = "Widget")]
pub struct WidgetRow {
    #[resource(id)]
    pub id: u32,
    #[resource(attr)]
    pub name: String,
}

impl From<WidgetRow> for Widget {
    fn from(row: WidgetRow) -> Self {
        Widget {
            id: row.id,
            name: row.name,
        }
    }
}

#[asset(
    row = WidgetRow,
    key = WidgetKey,
    profile = WidgetGrants,
    actions = WidgetAction,
    list = tenant,
    entity = shop_api::widgets::Widget
)]
pub struct WidgetByName;

/// Widgets in memory, and the names people have suggested.
#[derive(Clone, Default)]
pub struct Catalog(Arc<RwLock<Vec<WidgetRow>>>, Arc<RwLock<Vec<String>>>);

impl Catalog {
    /// A catalog holding `widgets`.
    pub fn new(widgets: Vec<WidgetRow>) -> Self {
        Self(Arc::new(RwLock::new(widgets)), Arc::default())
    }

    /// Every suggested name, oldest first.
    pub fn suggestions(&self) -> Vec<String> {
        self.1.read().unwrap().clone()
    }

    fn list(&self, contains: Option<&str>) -> Vec<Widget> {
        let widgets = self.0.read().unwrap();
        widgets
            .iter()
            .filter(|w| contains.is_none_or(|c| w.name.contains(c)))
            .cloned()
            .map(Widget::from)
            .collect()
    }

    fn rename(&self, id: u32, name: &str) -> Result<Widget, WidgetError> {
        let mut widgets = self.0.write().unwrap();
        if widgets.iter().any(|w| w.name == name) {
            return Err(WidgetError::NameTaken(name.to_owned()));
        }
        let widget = widgets.iter_mut().find(|w| w.id == id).expect("guarded");
        widget.name = name.to_owned();
        Ok(widget.clone().into())
    }
}

impl Fetch<Catalog> for WidgetRow {
    type Error = Infallible;
}

impl FetchByKey<Catalog> for WidgetRow {
    type Key = WidgetKey;

    async fn fetch(
        key: WidgetKey,
        src: &Catalog,
        _scope: &str,
    ) -> Result<Option<Self>, Infallible> {
        Ok(src
            .0
            .read()
            .unwrap()
            .iter()
            .find(|w| w.name == key.name)
            .cloned())
    }
}

impl FetchSubset for WidgetRow {
    type Filter = String;

    fn subset(scope: &str) -> String {
        scope.to_owned()
    }
}

/// How widget guards find the caller and the catalog.
pub struct WidgetGrants;

impl GrantProfile for WidgetGrants {
    type Ctx = CapabilityContext;
    type State = Catalog;
    type Source = FromState<Catalog>;
    type Error = Infallible;
}

/// Who sent a request, from the `x-role` header the demo signs in with.
pub struct Caller(pub String);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Caller {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Infallible> {
        let role = parts.headers.get("x-role").and_then(|v| v.to_str().ok());
        Ok(Caller(role.unwrap_or("anonymous").to_owned()))
    }
}

#[implements(shop_api::widgets::get_widget)]
async fn get_widget(widget: Granted<WidgetByName>) -> Json<Widget> {
    Json(widget.into_inner().into())
}

#[implements(shop_api::widgets::list_widgets)]
async fn list_widgets(
    _scope: Granted<Many<WidgetByName>>,
    State(catalog): State<Catalog>,
    Query(filter): Query<Filter>,
) -> Json<Vec<Widget>> {
    Json(catalog.list(filter.contains.as_deref()))
}

#[implements(shop_api::widgets::rename_widget)]
async fn rename_widget(
    widget: Granted<WidgetByName>,
    State(catalog): State<Catalog>,
    Valid(Json(rename)): Valid<Json<Rename>>,
) -> Result<Json<Widget>, WidgetError> {
    catalog.rename(widget.id, &rename.name).map(Json)
}

// `Caller` is server-only: the declaration doesn't name it, and the client never sends it.
#[implements(shop_api::widgets::suggest_name)]
async fn suggest_name(
    State(catalog): State<Catalog>,
    Caller(who): Caller,
    Json(suggestion): Json<Rename>,
) -> StatusCode {
    catalog
        .1
        .write()
        .unwrap()
        .push(format!("{} from {who}", suggestion.name));
    StatusCode::ACCEPTED
}

#[implements(shop_api::widgets::widget_label)]
async fn widget_label(widget: Granted<WidgetByName>) -> Attachment {
    let name = widget.into_inner().name;
    Attachment::new(format!("{name}\n"))
        .content_type("text/plain")
        .filename(format!("{name} label.txt"))
}

#[implements(shop_api::widgets::upload_photo)]
async fn upload_photo(_widget: Granted<WidgetByName>, photo: Bytes) -> Json<usize> {
    Json(photo.len())
}

#[implements(shop_api::widgets::upload_files)]
async fn upload_files(mut form: Multipart) -> Json<Vec<String>> {
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

#[implements(shop_api::widgets::widget_events)]
async fn widget_events(
    widget: Granted<WidgetByName>,
) -> SseStream<WidgetEvent, impl Stream<Item = Result<WidgetEvent, Infallible>>> {
    let name = widget.into_inner().name;
    SseStream::new(stream::iter([
        Ok(WidgetEvent::Renamed { name }),
        Ok(WidgetEvent::Deleted),
    ]))
}
