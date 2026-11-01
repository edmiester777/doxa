//! Where widgets live. Server only.

use std::convert::Infallible;
use std::sync::{Arc, RwLock};

use doxa::auth::{CapabilityContext, FromState, GrantProfile};
use doxa::policy::{Fetch, FetchByKey, FetchSubset};

use crate::widgets::{Widget, WidgetError, WidgetKey};

/// Widgets in memory, and the names people have suggested.
#[derive(Clone)]
pub struct Catalog(Arc<RwLock<Vec<Widget>>>, Arc<RwLock<Vec<String>>>);

impl Catalog {
    /// A catalog holding `widgets`.
    pub fn new(widgets: Vec<Widget>) -> Self {
        Self(Arc::new(RwLock::new(widgets)), Arc::default())
    }

    /// Every suggested name, oldest first.
    pub fn suggestions(&self) -> Vec<String> {
        self.1.read().unwrap().clone()
    }

    pub(crate) fn suggest(&self, name: String) {
        self.1.write().unwrap().push(name);
    }

    pub(crate) fn list(&self, contains: Option<&str>) -> Vec<Widget> {
        let widgets = self.0.read().unwrap();
        widgets
            .iter()
            .filter(|w| contains.is_none_or(|c| w.name.contains(c)))
            .cloned()
            .collect()
    }

    pub(crate) fn rename(&self, id: u32, name: &str) -> Result<Widget, WidgetError> {
        let mut widgets = self.0.write().unwrap();
        if widgets.iter().any(|w| w.name == name) {
            return Err(WidgetError::NameTaken(name.to_owned()));
        }
        let widget = widgets.iter_mut().find(|w| w.id == id).expect("guarded");
        widget.name = name.to_owned();
        Ok(widget.clone())
    }
}

impl Fetch<Catalog> for Widget {
    type Error = Infallible;
}

impl FetchByKey<Catalog> for Widget {
    type Key = WidgetKey;

    async fn fetch(key: WidgetKey, src: &Catalog, _scope: &str) -> Result<Option<Self>, Infallible> {
        Ok(src.0.read().unwrap().iter().find(|w| w.name == key.name).cloned())
    }
}

impl FetchSubset for Widget {
    type Filter = String;

    fn subset(scope: &str) -> String {
        scope.to_owned()
    }
}

/// How this app's guards find the caller and the catalog.
pub struct AppGrants;

impl GrantProfile for AppGrants {
    type Ctx = CapabilityContext;
    type State = Catalog;
    type Source = FromState<Catalog>;
    type Error = Infallible;
}
