//! Tests that find what a user sees: `screen.role(Role::Button).name("Save").click().await`.
//! A `Screen` renders into a `MemDom`; `find_*` runs tasks and due timers until a match shows.

#[cfg(feature = "react")]
mod fake;
mod role;

use std::rc::Rc;
use std::time::Duration;

use crate::dom::{MemDom, NodeId, Prop};
use crate::{App, IntoRoot, RootHandle};

#[cfg(feature = "react")]
pub use fake::{fake, FakeProps};
pub use role::Role;

/// A mounted app and the document it renders into.
pub struct Screen {
    dom: MemDom,
    timeout: Duration,
    _root: RootHandle,
}

/// What a query looks for.
#[derive(Debug, Clone)]
enum By {
    Role(Role, Option<String>),
    Text(String),
    Label(String),
}

/// A query that found nothing, or more than one thing, with the document it looked at.
#[non_exhaustive]
#[derive(Debug)]
pub enum ScreenError {
    NotFound {
        query: String,
        html: String,
    },
    Ambiguous {
        query: String,
        count: usize,
        html: String,
    },
}

impl std::fmt::Display for ScreenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScreenError::NotFound { query, html } => write!(f, "nothing is {query}\n\n{html}"),
            ScreenError::Ambiguous { query, count, html } => {
                write!(
                    f,
                    "{count} elements are {query}; narrow it with `.name(…)`\n\n{html}"
                )
            }
        }
    }
}

impl std::error::Error for ScreenError {}

impl Screen {
    /// Render `root`, a closure returning a view or a `Router`, as an app would.
    pub fn mount(root: impl IntoRoot) -> Screen {
        Screen::app(App::new(root))
    }

    /// Render a configured `App`.
    pub fn app(app: App) -> Screen {
        let dom = MemDom::new();
        let root = app.mount_on(Rc::new(dom.clone()), dom.body());
        Screen {
            dom,
            timeout: Duration::from_secs(1),
            _root: root,
        }
    }

    /// How far `find_*` moves the manual clock before giving up; a second by default.
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    pub fn dom(&self) -> &MemDom {
        &self.dom
    }

    /// Elements of `role`; narrow with [`Query::name`].
    pub fn role(&self, role: Role) -> Query<'_> {
        self.query(By::Role(role, None))
    }

    /// Elements whose own text is `text`, whitespace collapsed.
    pub fn text(&self, text: &str) -> Query<'_> {
        self.query(By::Text(text.to_owned()))
    }

    /// The form control a `<label>`, `aria-label` or `aria-labelledby` names `label`.
    pub fn label(&self, label: &str) -> Query<'_> {
        self.query(By::Label(label.to_owned()))
    }

    /// Wait for one element whose own text is `text`.
    pub async fn find_text(&self, text: &str) -> Result<NodeId, ScreenError> {
        self.text(text).find().await
    }

    fn query(&self, by: By) -> Query<'_> {
        Query { screen: self, by }
    }

    /// Run tasks until none can move, then yield so outside work (a test server) can too.
    pub async fn settle(&self) {
        for _ in 0..10 {
            doxa_client::task::run_until_stalled();
            yield_now().await;
        }
        doxa_client::task::run_until_stalled();
    }

    /// The next timer's deadline, if one is due within `timeout` of `start`.
    fn next_timer(&self, start: Duration) -> Option<Duration> {
        let clock = doxa_client::clock::manual();
        clock
            .next_deadline()
            .filter(|d| *d <= start + self.timeout)
            .map(|d| d.saturating_sub(clock.now()))
    }
}

/// Elements a [`Screen`] query matches.
pub struct Query<'s> {
    screen: &'s Screen,
    by: By,
}

impl Query<'_> {
    /// Only those whose accessible name is `name`.
    pub fn name(mut self, name: &str) -> Self {
        if let By::Role(_, n) = &mut self.by {
            *n = Some(name.to_owned());
        }
        self
    }

    /// Every match now, in document order.
    pub fn all(&self) -> Vec<NodeId> {
        let dom = &self.screen.dom;
        let els = role::elements(dom);
        match &self.by {
            By::Role(r, name) => els
                .into_iter()
                .filter(|&n| role::role_of(dom, n).as_deref() == Some(r.as_str()))
                .filter(|&n| {
                    name.as_ref()
                        .is_none_or(|want| role::name_of(dom, n) == *want)
                })
                .collect(),
            By::Text(t) => els
                .into_iter()
                .filter(|&n| role::own_text(dom, n) == *t)
                .collect(),
            By::Label(l) => els
                .into_iter()
                .filter(|&n| {
                    (role::labels_of(dom, n).is_some()
                        || dom.attr(n, "aria-label").is_some()
                        || dom.attr(n, "aria-labelledby").is_some())
                        && role::name_of(dom, n) == *l
                })
                .collect(),
        }
    }

    /// The one match now.
    pub fn get(&self) -> Result<NodeId, ScreenError> {
        match self.all().as_slice() {
            [one] => Ok(*one),
            [] => Err(ScreenError::NotFound {
                query: self.describe(),
                html: self.screen.dom.html(self.screen.dom.body()),
            }),
            many => Err(ScreenError::Ambiguous {
                query: self.describe(),
                count: many.len(),
                html: self.screen.dom.html(self.screen.dom.body()),
            }),
        }
    }

    /// Wait for the one match: run tasks, then due timers, until it shows or the timeout passes.
    pub async fn find(&self) -> Result<NodeId, ScreenError> {
        let start = doxa_client::clock::manual().now();
        loop {
            self.screen.settle().await;
            if let Ok(n) = self.get() {
                return Ok(n);
            }
            match self.screen.next_timer(start) {
                Some(wait) => self.screen.dom.advance(wait),
                None => return self.get(),
            }
        }
    }

    /// Wait for it, click it, and let what that starts finish; panics with the document if it never shows.
    pub async fn click(self) {
        let node = self.found().await;
        self.screen.dom.click(node);
        self.screen.settle().await;
    }

    /// Wait for it and type `text` after its current value, firing `input`.
    pub async fn type_text(self, text: &str) {
        let node = self.found().await;
        let dom = &self.screen.dom;
        let current = match dom.prop(node, "value") {
            Some(Prop::Str(s)) => s,
            _ => dom.attr(node, "value").unwrap_or_default(),
        };
        dom.input(node, &(current + text));
        self.screen.settle().await;
    }

    async fn found(&self) -> NodeId {
        self.find().await.unwrap_or_else(|e| panic!("{e}"))
    }

    fn describe(&self) -> String {
        match &self.by {
            By::Role(r, None) => format!("a {}", r.as_str()),
            By::Role(r, Some(n)) => format!("a {} named {n:?}", r.as_str()),
            By::Text(t) => format!("text {t:?}"),
            By::Label(l) => format!("labelled {l:?}"),
        }
    }
}

/// Pending once, so the executor running the test polls its other tasks.
fn yield_now() -> impl std::future::Future<Output = ()> {
    let mut yielded = false;
    std::future::poll_fn(move |cx| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
}
