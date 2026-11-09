//! Where widgets live, and how a guard finds one.

use std::convert::Infallible;
use std::sync::{Arc, RwLock};

use doxa::auth::{CapabilityContext, FromState, GrantProfile};
use doxa::policy::{Fetch, FetchByKey, FetchSubset};
use doxa::{asset, PolicyResource};

use crate::widgets::{Widget, WidgetAction, WidgetError, WidgetKey};

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
    entity = Widget
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

    /// Note a suggested name.
    pub fn suggest(&self, suggestion: String) {
        self.1.write().unwrap().push(suggestion);
    }

    /// Every widget, or those whose name holds `contains`.
    pub fn list(&self, contains: Option<&str>) -> Vec<Widget> {
        let widgets = self.0.read().unwrap();
        widgets
            .iter()
            .filter(|w| contains.is_none_or(|c| w.name.contains(c)))
            .cloned()
            .map(Widget::from)
            .collect()
    }

    /// Rename widget `id`, unless another has the name.
    pub fn rename(&self, id: u32, name: &str) -> Result<Widget, WidgetError> {
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

/// Each field of `form` as `name=size`, or `name:file=size` for a file.
pub async fn field_sizes(mut form: axum::extract::Multipart) -> Vec<String> {
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
    fields
}
