//! `App`: the client, global providers, theme and plugins, mounted at one element.

use std::any::{Any, TypeId};
use std::rc::Rc;

use doxa_client::{CacheConfig, ClientConfig};

use crate::component::{Component, RenderFuture};
use crate::dom::{Dom, NodeId};
use crate::plugin::{Fills, Plugin};
use crate::router::{self, Router};
use crate::runtime::{self, Instance};
use crate::theme::{self, Theme};
use crate::{IntoView, View};

/// A whole app, ready to mount.
///
/// ```ignore
/// App::new(Router::new().page::<WidgetPage>())
///     .config(ClientConfig::default().cookies())
///     .theme(LIGHT)
///     .mount("#app");
/// ```
#[must_use = "an app does nothing until it is mounted"]
pub struct App {
    root: Rc<dyn Fn() -> View>,
    router: Option<Router>,
    config: ClientConfig,
    cache: Option<CacheConfig>,
    provided: Vec<(TypeId, Rc<dyn Any>)>,
    theme: Option<Theme>,
    plugins: Vec<Box<dyn Plugin>>,
}

/// What an app renders: a [`Router`], or a function returning its view.
pub trait IntoRoot {
    #[doc(hidden)]
    fn into_root(self) -> (Rc<dyn Fn() -> View>, Option<Router>);
}

impl IntoRoot for Router {
    fn into_root(self) -> (Rc<dyn Fn() -> View>, Option<Router>) {
        let r = self.clone();
        (Rc::new(move || r.view()), Some(self))
    }
}

impl<F: Fn() -> V + 'static, V: IntoView> IntoRoot for F {
    fn into_root(self) -> (Rc<dyn Fn() -> View>, Option<Router>) {
        (Rc::new(move || self().into_view()), None)
    }
}

impl App {
    /// An app rendering `root`.
    pub fn new(root: impl IntoRoot) -> Self {
        let (root, router) = root.into_root();
        Self {
            root,
            router,
            config: ClientConfig::default(),
            cache: None,
            provided: Vec::new(),
            theme: None,
            plugins: Vec::new(),
        }
    }

    /// How routes are called: credentials and transport.
    pub fn config(mut self, config: ClientConfig) -> Self {
        self.config = config;
        self
    }

    /// How long responses stay fresh.
    pub fn cache(mut self, cache: CacheConfig) -> Self {
        self.cache = Some(cache);
        self
    }

    /// A value every component can read with `context::<T>()`.
    pub fn provide<T: Clone + 'static>(mut self, value: T) -> Self {
        self.provided.retain(|(t, _)| *t != TypeId::of::<T>());
        self.provided.push((TypeId::of::<T>(), Rc::new(value)));
        self
    }

    /// The theme to start with; change it later with `set_theme`.
    pub fn theme(mut self, theme: Theme) -> Self {
        self.theme = Some(theme);
        self
    }

    /// Install a plugin.
    pub fn plugin(mut self, plugin: impl Plugin) -> Self {
        self.plugins.push(Box::new(plugin));
        self
    }

    /// Mount into the page element matching `selector`. Only a browser has a page;
    /// natively, mount a [`MemDom`](crate::dom::MemDom) with [`App::mount_on`].
    pub fn mount(self, selector: &str) {
        #[cfg(target_arch = "wasm32")]
        {
            let dom = Rc::new(crate::dom::WebDom::new());
            let at = dom
                .query(selector)
                .unwrap_or_else(|| panic!("no element matches `{selector}`"));
            self.mount_on(dom, at);
        }
        #[cfg(not(target_arch = "wasm32"))]
        panic!(
            "`App::mount({selector:?})` needs a browser; natively, use `mount_on` with a `MemDom`"
        );
    }

    /// Mount at `at` in `dom`; tests pass a [`MemDom`](crate::dom::MemDom).
    pub fn mount_on(self, dom: Rc<dyn Dom>, at: NodeId) {
        let mut config = self.config;
        if let Some(cache) = self.cache {
            config = config.cache(cache);
        }
        config.install();
        runtime::set_dom(dom.clone());
        theme::set_host(dom.query("html").unwrap_or(at));
        if let Some(t) = self.theme {
            theme::set_theme(t);
        }
        if let Some(r) = self.router {
            router::install(r);
        }
        let plugins: Rc<[Box<dyn Plugin>]> = self.plugins.into();
        let mut provided = self.provided;
        provided.push((TypeId::of::<Fills>(), Rc::new(Fills::collect(&plugins))));

        let root = self.root;
        let props: Rc<dyn Any> = Rc::new(RootProps(Rc::new(move || {
            plugins.iter().fold(root(), |view, p| p.wrap(view))
        })));
        let inst = Instance::new(
            Root::NAME,
            TypeId::of::<Root>(),
            None,
            |p| Root::render(p.downcast_ref::<RootProps>().expect("root props").clone()),
            props,
            at,
        );
        *inst.contexts.borrow_mut() = provided;
        runtime::run(&inst);
        ROOT.with(|r| *r.borrow_mut() = Some(inst));
    }
}

thread_local! {
    static ROOT: std::cell::RefCell<Option<Rc<Instance>>> = const { std::cell::RefCell::new(None) };
}

struct Root;

#[derive(Clone)]
struct RootProps(Rc<dyn Fn() -> View>);

impl Component for Root {
    type Props = RootProps;
    const NAME: &'static str = "App";

    fn render(props: RootProps) -> RenderFuture {
        RenderFuture::ready(Ok((props.0)()))
    }
}
