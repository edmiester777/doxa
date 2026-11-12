//! What sign-in needs from the page it runs in, so a test can be that page.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// The page sign-in runs in: its URL, its `sessionStorage`, randomness and its sibling tabs.
pub trait Host: 'static {
    /// The page's full URL.
    fn url(&self) -> String;
    /// Leave for `url`, as signing in and out do.
    fn redirect(&self, url: &str);
    /// Change the URL without a reload or a history entry, as stripping the callback does.
    fn replace(&self, url: &str);
    /// A `sessionStorage` value.
    fn load(&self, key: &str) -> Option<String>;
    /// Keep `value` for this tab's session.
    fn store(&self, key: &str, value: &str);
    /// Forget `key`.
    fn forget(&self, key: &str);
    /// Cryptographically random bytes.
    fn random(&self, out: &mut [u8]);
    /// Tell this app's other tabs `message`.
    fn post(&self, message: &str);
    /// Hear what other tabs post.
    fn listen(&self, f: Box<dyn Fn(String)>);
}

type Listener = Rc<dyn Fn(String)>;

/// A page held in memory, for tests: `tab()` opens another that shares its broadcasts.
#[derive(Clone)]
pub struct MemoryHost {
    url: Rc<RefCell<String>>,
    left_for: Rc<RefCell<Option<String>>>,
    storage: Rc<RefCell<HashMap<String, String>>>,
    seed: Rc<RefCell<u64>>,
    bus: Rc<RefCell<Vec<(usize, Listener)>>>,
    tabs: Rc<std::cell::Cell<usize>>,
    id: usize,
}

impl MemoryHost {
    /// A page at `url`.
    pub fn new(url: &str) -> Self {
        MemoryHost {
            url: Rc::new(RefCell::new(url.to_owned())),
            left_for: Rc::default(),
            storage: Rc::default(),
            seed: Rc::new(RefCell::new(1)),
            bus: Rc::default(),
            tabs: Rc::new(std::cell::Cell::new(1)),
            id: 0,
        }
    }

    /// Another tab of the same app, at `url`: its own storage, the same broadcasts.
    pub fn tab(&self, url: &str) -> Self {
        MemoryHost {
            url: Rc::new(RefCell::new(url.to_owned())),
            left_for: Rc::default(),
            storage: Rc::default(),
            seed: Rc::new(RefCell::new(
                self.seed.borrow().wrapping_mul(7919).wrapping_add(13),
            )),
            bus: self.bus.clone(),
            tabs: self.tabs.clone(),
            id: {
                let id = self.tabs.get();
                self.tabs.set(id + 1);
                id
            },
        }
    }

    /// Where the page last went with [`Host::redirect`].
    pub fn left_for(&self) -> Option<String> {
        self.left_for.borrow().clone()
    }

    /// Arrive at `url`, as the browser does coming back from the issuer.
    pub fn arrive(&self, url: &str) {
        *self.url.borrow_mut() = url.to_owned();
        *self.left_for.borrow_mut() = None;
    }
}

impl Host for MemoryHost {
    fn url(&self) -> String {
        self.url.borrow().clone()
    }

    fn redirect(&self, url: &str) {
        *self.left_for.borrow_mut() = Some(url.to_owned());
    }

    fn replace(&self, url: &str) {
        *self.url.borrow_mut() = url.to_owned();
    }

    fn load(&self, key: &str) -> Option<String> {
        self.storage.borrow().get(key).cloned()
    }

    fn store(&self, key: &str, value: &str) {
        self.storage
            .borrow_mut()
            .insert(key.to_owned(), value.to_owned());
    }

    fn forget(&self, key: &str) {
        self.storage.borrow_mut().remove(key);
    }

    fn random(&self, out: &mut [u8]) {
        let mut s = self.seed.borrow_mut();
        for b in out {
            // xorshift: deterministic, which is all a test wants.
            *s ^= *s << 13;
            *s ^= *s >> 7;
            *s ^= *s << 17;
            *b = *s as u8;
        }
    }

    fn post(&self, message: &str) {
        let others: Vec<_> = self
            .bus
            .borrow()
            .iter()
            .filter(|(id, _)| *id != self.id)
            .map(|(_, f)| f.clone())
            .collect();
        for f in others {
            f(message.to_owned());
        }
    }

    fn listen(&self, f: Box<dyn Fn(String)>) {
        self.bus.borrow_mut().push((self.id, Rc::from(f)));
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) use browser::Browser;

#[cfg(target_arch = "wasm32")]
mod browser {
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsCast;

    /// The real page.
    pub struct Browser {
        channel: Option<web_sys::BroadcastChannel>,
    }

    impl Browser {
        pub fn new() -> Self {
            Browser {
                channel: web_sys::BroadcastChannel::new("doxa-oidc").ok(),
            }
        }
    }

    fn window() -> web_sys::Window {
        web_sys::window().expect("a window")
    }

    impl super::Host for Browser {
        fn url(&self) -> String {
            window().location().href().unwrap_or_default()
        }

        fn redirect(&self, url: &str) {
            let _ = window().location().assign(url);
        }

        fn replace(&self, url: &str) {
            if let Ok(history) = window().history() {
                let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(url));
            }
        }

        fn load(&self, key: &str) -> Option<String> {
            window().session_storage().ok()??.get_item(key).ok()?
        }

        fn store(&self, key: &str, value: &str) {
            if let Ok(Some(s)) = window().session_storage() {
                let _ = s.set_item(key, value);
            }
        }

        fn forget(&self, key: &str) {
            if let Ok(Some(s)) = window().session_storage() {
                let _ = s.remove_item(key);
            }
        }

        fn random(&self, out: &mut [u8]) {
            let crypto = window().crypto().expect("crypto.getRandomValues");
            crypto
                .get_random_values_with_u8_array(out)
                .expect("crypto.getRandomValues");
        }

        fn post(&self, message: &str) {
            if let Some(c) = &self.channel {
                let _ = c.post_message(&message.into());
            }
        }

        fn listen(&self, f: Box<dyn Fn(String)>) {
            let Some(c) = &self.channel else { return };
            let on =
                Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
                    if let Some(s) = e.data().as_string() {
                        f(s);
                    }
                });
            c.set_onmessage(Some(on.as_ref().unchecked_ref()));
            // The listener lives as long as the page.
            on.forget();
        }
    }
}
