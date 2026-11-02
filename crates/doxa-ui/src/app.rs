//! `App`: providers, theme and plugins, mounted at an element. A page may hold several roots;
//! they share one document per thread.

use std::any::{Any, TypeId};
use std::cell::RefCell;
use std::rc::Rc;

use crate::component::{Component, RenderFuture};
use crate::dom::{Dom, NodeId};
use crate::plugin::{Fills, Plugin};
use crate::reconcile;
use crate::router::{self, Router};
use crate::runtime::{self, Instance};
use crate::theme::{self, Theme};
use crate::{IntoView, View};

/// A whole app, ready to mount.
///
/// ```ignore
/// layers().push(cookies());
/// App::new(Router::new().page::<WidgetPage>())
///     .theme(LIGHT)
///     .mount("#app");
/// ```
#[must_use = "an app does nothing until it is mounted"]
pub struct App {
    root: Rc<dyn Fn() -> View>,
    router: Option<Router>,
    provided: Vec<(TypeId, Rc<dyn Any>)>,
    theme: Option<Theme>,
    plugins: Vec<Box<dyn Plugin>>,
    embedded: bool,
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
            provided: Vec::new(),
            theme: None,
            plugins: Vec::new(),
            embedded: false,
        }
    }

    /// An app embedded in a page it doesn't own: no router, and its theme on its own element.
    pub fn embedded<V: IntoView>(root: impl Fn() -> V + 'static) -> Self {
        Self {
            embedded: true,
            ..Self::new(root)
        }
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
    /// The root stays mounted for the page's life.
    pub fn mount(self, selector: &str) {
        #[cfg(target_arch = "wasm32")]
        {
            let dom = runtime::try_dom().unwrap_or_else(|| Rc::new(crate::dom::WebDom::new()));
            let at = dom
                .query(selector)
                .unwrap_or_else(|| panic!("no element matches `{selector}`"));
            self.mount_on(dom, at).keep();
        }
        #[cfg(not(target_arch = "wasm32"))]
        panic!(
            "`App::mount({selector:?})` needs a browser; natively, use `mount_on` with a `MemDom`"
        );
    }

    /// Mount at `at` in `dom`; tests pass a [`MemDom`](crate::dom::MemDom). Mounting on
    /// another document than the current one first unmounts every root on the old one.
    pub fn mount_on(self, dom: Rc<dyn Dom>, at: NodeId) -> RootHandle {
        crate::hot::install();
        if !runtime::is_dom(&dom) {
            reconcile::finish_leaving();
            let old: Vec<_> = ROOTS.with(|r| r.borrow_mut().drain(..).collect());
            for (inst, _) in old {
                reconcile::unmount_root(&inst);
            }
            runtime::set_dom(dom.clone());
            theme::clear_hosts();
        }
        let host = if self.embedded {
            at
        } else {
            dom.query("html").unwrap_or(at)
        };
        theme::add_host(host);
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
        let id = inst.id;
        ROOTS.with(|r| r.borrow_mut().push((inst.clone(), host)));
        runtime::run(&inst);
        RootHandle { id }
    }
}

thread_local! {
    static ROOTS: RefCell<Vec<(Rc<Instance>, NodeId)>> = const { RefCell::new(Vec::new()) };
}

/// A mounted root. Dropping it unmounts the root: its effects stop and its nodes go.
#[must_use = "dropping a RootHandle unmounts its root; call `.keep()` to keep it mounted"]
pub struct RootHandle {
    id: u64,
}

impl RootHandle {
    /// Names this root; each island records the root it is in.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Render the root again, as its own state changing would.
    pub(crate) fn refresh(&self) {
        if let Some(inst) = Instance::find(self.id) {
            runtime::schedule(&inst);
        }
    }

    /// Keep the root mounted for the page's life.
    pub fn keep(self) {
        std::mem::forget(self);
    }
}

impl Drop for RootHandle {
    fn drop(&mut self) {
        let found = ROOTS.with(|r| {
            let mut r = r.borrow_mut();
            let at = r.iter().position(|(i, _)| i.id == self.id)?;
            Some(r.remove(at))
        });
        if let Some((inst, host)) = found {
            reconcile::unmount_root(&inst);
            theme::remove_host(host);
        }
    }
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
