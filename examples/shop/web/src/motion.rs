//! Two directives an app could take from a library: an exit animation and a FLIP move.

use doxa::ui::{Directive, NodeRef};
use futures::future::LocalBoxFuture;

/// `use:exit={"leaving"}`: add `class` to a removed element and keep it until its
/// animation ends. Without a CSS animation on that class it goes at once.
pub fn exit(class: &'static str) -> Exit {
    Exit(class)
}

/// See [`exit`].
#[derive(Clone)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub struct Exit(&'static str);

impl Directive for Exit {
    #[cfg(target_arch = "wasm32")]
    fn leaving(&mut self, node: NodeRef) -> Option<LocalBoxFuture<'static, ()>> {
        use wasm_bindgen::JsCast;
        let el: web_sys::HtmlElement = node.raw()?.dyn_into().ok()?;
        el.class_list().add_1(self.0).ok()?;
        let animated = web_sys::window()?
            .get_computed_style(&el)
            .ok()??
            .get_property_value("animation-name")
            .is_ok_and(|n| n != "none");
        animated.then(|| Box::pin(once(el.into(), "animationend")) as LocalBoxFuture<'static, ()>)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn leaving(&mut self, _: NodeRef) -> Option<LocalBoxFuture<'static, ()>> {
        None
    }
}

/// `use:flip`: when a keyed reorder moves the element, slide it from where it was.
pub fn flip() -> Flip {
    Flip::default()
}

/// See [`flip`].
#[derive(Clone, Default)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub struct Flip {
    /// Left and top before the move.
    from: Option<(f64, f64)>,
}

impl Directive for Flip {
    fn update(&mut self, _: Self) {}

    #[cfg(target_arch = "wasm32")]
    fn before_move(&mut self, node: NodeRef) {
        self.from = element(node).map(|el| {
            let r = el.get_bounding_client_rect();
            (r.left(), r.top())
        });
    }

    #[cfg(target_arch = "wasm32")]
    fn after_move(&mut self, node: NodeRef) {
        let (Some((x, y)), Some(el)) = (self.from.take(), element(node)) else {
            return;
        };
        let r = el.get_bounding_client_rect();
        let (dx, dy) = (x - r.left(), y - r.top());
        if dx == 0.0 && dy == 0.0 {
            return;
        }
        let frames = js_sys::Array::of2(
            &frame(&format!("translate({dx}px, {dy}px)")),
            &frame("none"),
        );
        // `Element.animate` is behind web-sys's unstable APIs.
        if let Ok(animate) = js_sys::Reflect::get(&el, &"animate".into()) {
            let animate: js_sys::Function = animate.into();
            let _ = animate.call2(&el, &frames, &200.into());
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn element(node: NodeRef) -> Option<web_sys::Element> {
    use wasm_bindgen::JsCast;
    node.raw()?.dyn_into().ok()
}

#[cfg(target_arch = "wasm32")]
fn frame(transform: &str) -> js_sys::Object {
    let f = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&f, &"transform".into(), &transform.into());
    f
}

/// Resolves the first time `target` fires `event`.
#[cfg(target_arch = "wasm32")]
async fn once(target: web_sys::EventTarget, event: &'static str) {
    use wasm_bindgen::{closure::Closure, JsCast};
    let (tx, rx) = futures::channel::oneshot::channel::<()>();
    let tx = std::cell::RefCell::new(Some(tx));
    let cb = Closure::<dyn Fn()>::new(move || {
        if let Some(tx) = tx.borrow_mut().take() {
            let _ = tx.send(());
        }
    });
    let opts = web_sys::AddEventListenerOptions::new();
    opts.set_once(true);
    let _ = target.add_event_listener_with_callback_and_add_event_listener_options(
        event,
        cb.as_ref().unchecked_ref(),
        &opts,
    );
    let _ = rx.await;
    drop(cb);
}
