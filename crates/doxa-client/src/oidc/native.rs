//! [`NativeHost`]: sign-in from inside a native shell, through the system browser.

use std::cell::RefCell;
use std::rc::Rc;

use super::{default_host, origin, pkce, Host};

/// The query parameter the callback comes back to the page in.
const CALLBACK: &str = "doxa_oidc";

/// The page inside a doxa native app. The issuer opens in the system browser, and the shell
/// brings its callback back. `redirect_uri` must be one of the app's `schemes` or an
/// `oidc_loopback` port.
pub struct NativeHost {
    page: Rc<dyn Host>,
    abandoned: Rc<RefCell<Option<Abandoned>>>,
}

type Abandoned = Rc<dyn Fn()>;

impl NativeHost {
    /// The app's page.
    pub fn new() -> Self {
        Self::over(default_host())
    }

    fn over(page: Rc<dyn Host>) -> Self {
        NativeHost {
            page,
            abandoned: Rc::default(),
        }
    }
}

impl Default for NativeHost {
    fn default() -> Self {
        Self::new()
    }
}

impl Host for NativeHost {
    /// The callback the shell brought back, while the page holds one; otherwise the page's URL.
    fn url(&self) -> String {
        let url = self.page.url();
        pkce::query(&url)
            .into_iter()
            .find_map(|(k, v)| (k == CALLBACK).then_some(v))
            .unwrap_or(url)
    }

    fn redirect(&self, url: &str) {
        let here = origin(&self.page.url());
        if origin(url) == here {
            return self.page.redirect(url);
        }
        let (page, abandoned) = (self.page.clone(), self.abandoned.clone());
        let url = url.to_owned();
        crate::task::spawn(async move {
            let caught: Result<Option<String>, _> =
                crate::native::invoke("plugin:doxa|sign_in", &serde_json::json!({ "url": url }))
                    .await;
            match caught {
                Ok(Some(callback)) => {
                    page.redirect(&format!("{here}/?{}", pkce::form(&[(CALLBACK, &callback)])))
                }
                Ok(None) => {}
                Err(_) => {
                    let f = abandoned.borrow().clone();
                    if let Some(f) = f {
                        f()
                    }
                }
            }
        });
    }

    fn replace(&self, url: &str) {
        self.page.replace(url)
    }

    fn load(&self, key: &str) -> Option<String> {
        self.page.load(key)
    }

    fn store(&self, key: &str, value: &str) {
        self.page.store(key, value)
    }

    fn forget(&self, key: &str) {
        self.page.forget(key)
    }

    fn random(&self, out: &mut [u8]) {
        self.page.random(out)
    }

    fn post(&self, message: &str) {
        self.page.post(message)
    }

    fn listen(&self, f: Box<dyn Fn(String)>) {
        self.page.listen(f)
    }

    fn on_abandoned(&self, f: Box<dyn Fn()>) {
        *self.abandoned.borrow_mut() = Some(Rc::from(f));
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::oidc::MemoryHost;

    #[test]
    fn the_brought_back_callback_is_the_url_until_replaced() {
        let page = MemoryHost::new("http://127.0.0.1:4000/");
        let host = NativeHost::over(Rc::new(page.clone()));
        let cb = "acme:/callback?code=c&state=s";
        page.replace(&format!(
            "http://127.0.0.1:4000/?{}",
            pkce::form(&[(CALLBACK, cb)])
        ));
        assert_eq!(host.url(), cb);
        host.replace("http://127.0.0.1:4000/orders");
        assert_eq!(host.url(), "http://127.0.0.1:4000/orders");
    }

    #[test]
    fn same_origin_stays_in_the_page_and_a_failed_sign_in_is_abandoned() {
        let page = MemoryHost::new("http://127.0.0.1:4000/");
        let host = NativeHost::over(Rc::new(page.clone()));
        let gave_up = Rc::new(Cell::new(false));
        let g = gave_up.clone();
        host.on_abandoned(Box::new(move || g.set(true)));
        host.redirect("http://127.0.0.1:4000/after");
        assert_eq!(
            page.left_for().as_deref(),
            Some("http://127.0.0.1:4000/after")
        );
        // Off wasm there's no shell, so the issuer redirect fails.
        host.redirect("https://id.example/auth?redirect_uri=acme%3A%2Fcb");
        crate::task::run_until_stalled();
        assert!(gave_up.get());
    }
}
