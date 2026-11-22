//! `sign_in`: a native sign-in in the system browser, its callback caught on a listed loopback
//! port or app scheme and handed back to the page.

use std::sync::Mutex;
use std::time::Duration;

use tauri::{AppHandle, Manager, Runtime, Url, WebviewWindow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

/// How long a sign-in waits for its callback.
const TIMEOUT: Duration = Duration::from_secs(300);

const RETURN_PAGE: &str = "<!doctype html><meta charset=utf-8><title>Signed in</title>\
<body style=\"font:16px system-ui;margin:4rem auto;max-width:28rem\">\
<p>You're signed in. You can close this tab and return to the app.</p>";

/// Where a callback may come back to: `[package.metadata.doxa.native]`'s `schemes` and
/// `oidc_loopback`.
pub(crate) struct Policy {
    pub schemes: Vec<String>,
    pub loopback: Vec<u16>,
}

/// The scheme callback a sign-in is waiting for.
#[derive(Default)]
pub(crate) struct Waiting(Mutex<Option<(String, oneshot::Sender<String>)>>);

impl Waiting {
    /// Takes `url` if a sign-in is waiting for it; then it isn't an ordinary deep link.
    pub(crate) fn take(&self, url: &str) -> bool {
        let mut w = self.0.lock().expect("waiting sign-in");
        match w.as_ref() {
            Some((prefix, _)) if base(url) == *prefix => {
                if let Some((_, tx)) = w.take() {
                    let _ = tx.send(url.to_owned());
                }
                true
            }
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq)]
enum Plan {
    /// Sign-out: open it, wait for nothing.
    Open,
    Loopback {
        port: u16,
        path: String,
        base: String,
    },
    Scheme {
        base: String,
    },
}

/// `url` without its query or fragment.
fn base(url: &str) -> String {
    url.split(['?', '#']).next().unwrap_or_default().to_owned()
}

fn loopback_host(u: &Url) -> bool {
    matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
}

/// What to do for the issuer URL `url`, or why it's refused.
fn plan(url: &str, policy: &Policy) -> Result<Plan, String> {
    let u = Url::parse(url).map_err(|e| format!("sign-in URL: {e}"))?;
    let secure = u.scheme() == "https" || (u.scheme() == "http" && loopback_host(&u));
    if !secure {
        return Err(format!(
            "sign-in goes to {}, which isn't https",
            u.origin().ascii_serialization()
        ));
    }
    let param = |k: &str| {
        u.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
    };
    let (back, sign_out) = match (param("redirect_uri"), param("post_logout_redirect_uri")) {
        (Some(r), _) => (r, false),
        (None, Some(r)) => (r, true),
        (None, None) => return Err("the sign-in URL has no redirect_uri".into()),
    };
    let r = Url::parse(&back).map_err(|e| format!("redirect_uri {back}: {e}"))?;
    let listed = if policy.schemes.iter().any(|s| s == r.scheme()) {
        Plan::Scheme { base: base(&back) }
    } else if r.scheme() == "http" && loopback_host(&r) {
        match r.port() {
            Some(port) if policy.loopback.contains(&port) => Plan::Loopback {
                port,
                path: r.path().to_owned(),
                base: base(&back),
            },
            _ => {
                return Err(format!(
                    "redirect_uri {back}: its port isn't in `oidc_loopback` in [package.metadata.doxa.native]"
                ))
            }
        }
    } else {
        return Err(format!(
            "redirect_uri {back} is neither one of the app's `schemes` nor a loopback port in `oidc_loopback`"
        ));
    };
    Ok(if sign_out { Plan::Open } else { listed })
}

/// Opens `url` in the system browser; resolves with the callback URL, or `None` for a sign-out.
#[tauri::command]
pub(crate) async fn sign_in<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    url: String,
) -> Result<Option<String>, String> {
    let plan = {
        let policy = app.state::<Policy>();
        plan(&url, &policy)?
    };
    // Bound before the browser opens, so a quick issuer can't beat it.
    let listener = match &plan {
        Plan::Loopback { port, .. } => Some(
            tokio::net::TcpListener::bind(("127.0.0.1", *port))
                .await
                .map_err(|e| format!("listening on 127.0.0.1:{port} for the sign-in: {e}"))?,
        ),
        _ => None,
    };
    let scheme = match &plan {
        Plan::Scheme { base } => {
            let (tx, rx) = oneshot::channel();
            // A newer sign-in replaces one still waiting; the old one's receiver closes.
            *app.state::<Waiting>().0.lock().expect("waiting sign-in") = Some((base.clone(), tx));
            Some(rx)
        }
        _ => None,
    };
    {
        use tauri_plugin_opener::OpenerExt;
        app.opener()
            .open_url(url.as_str(), None::<&str>)
            .map_err(|e| format!("opening the browser: {e}"))?;
    }
    let caught = match (plan, listener, scheme) {
        (Plan::Open, ..) => return Ok(None),
        (Plan::Loopback { path, base, .. }, Some(l), _) => {
            tokio::time::timeout(TIMEOUT, catch(l, &path, &base)).await
        }
        (Plan::Scheme { .. }, _, Some(rx)) => {
            tokio::time::timeout(TIMEOUT, async {
                rx.await.map_err(|_| "another sign-in started".to_owned())
            })
            .await
        }
        _ => unreachable!("each plan has its listener"),
    };
    let callback = caught.map_err(|_| "the sign-in timed out".to_owned())??;
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
    Ok(Some(callback))
}

/// Serves requests on `l` until one for `path`, answering it with a page that sends the user
/// back to the app.
async fn catch(l: tokio::net::TcpListener, path: &str, base: &str) -> Result<String, String> {
    loop {
        let (mut s, _) = l.accept().await.map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 8192];
        let mut n = 0;
        while n < buf.len() {
            match s.read(&mut buf[n..]).await {
                Ok(0) | Err(_) => break,
                Ok(k) => n += k,
            }
            if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&buf[..n]);
        let target = head
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("GET "))
            .and_then(|l| l.split(' ').next())
            .unwrap_or_default()
            .to_owned();
        let (got, query) = target.split_once('?').unwrap_or((&target, ""));
        if got != path {
            let _ = s
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await;
            continue;
        }
        let reply = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{RETURN_PAGE}",
            RETURN_PAGE.len()
        );
        let _ = s.write_all(reply.as_bytes()).await;
        return Ok(match query.is_empty() {
            true => base.to_owned(),
            false => format!("{base}?{query}"),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            schemes: vec!["acme".into()],
            loopback: vec![47999],
        }
    }

    fn at(endpoint: &str, pairs: &[(&str, &str)]) -> String {
        let mut u = Url::parse(endpoint).unwrap();
        u.query_pairs_mut().extend_pairs(pairs);
        u.into()
    }

    fn auth(redirect: &str) -> String {
        at(
            "https://id.example/auth",
            &[
                ("response_type", "code"),
                ("redirect_uri", redirect),
                ("state", "s"),
            ],
        )
    }

    #[test]
    fn only_a_listed_scheme_or_loopback_port_is_caught() {
        assert_eq!(
            plan(&auth("acme:/callback"), &policy()),
            Ok(Plan::Scheme {
                base: "acme:/callback".into()
            })
        );
        assert_eq!(
            plan(&auth("http://127.0.0.1:47999/cb"), &policy()),
            Ok(Plan::Loopback {
                port: 47999,
                path: "/cb".into(),
                base: "http://127.0.0.1:47999/cb".into()
            })
        );
        assert!(plan(&auth("http://127.0.0.1:48000/cb"), &policy())
            .unwrap_err()
            .contains("oidc_loopback"));
        assert!(plan(&auth("https://evil.example/cb"), &policy()).is_err());
        assert!(plan(&auth("other:/cb"), &policy()).is_err());
    }

    #[test]
    fn the_issuer_must_be_https_unless_it_is_local() {
        let r = "redirect_uri=acme%3A%2Fcb";
        assert!(plan(&format!("http://id.example/auth?{r}"), &policy()).is_err());
        assert!(plan(&format!("http://localhost:8080/auth?{r}"), &policy()).is_ok());
        assert!(plan("https://id.example/auth", &policy()).is_err());
    }

    #[test]
    fn sign_out_is_opened_and_not_waited_for() {
        let out = at(
            "https://id.example/logout",
            &[("post_logout_redirect_uri", "acme:/")],
        );
        assert_eq!(plan(&out, &policy()), Ok(Plan::Open));
    }

    #[test]
    fn a_scheme_callback_is_taken_once_and_only_if_it_matches() {
        let w = Waiting::default();
        let (tx, mut rx) = oneshot::channel();
        *w.0.lock().unwrap() = Some(("acme:/callback".into(), tx));
        assert!(!w.take("acme:/other?x=1"));
        assert!(w.take("acme:/callback?code=c&state=s"));
        assert_eq!(rx.try_recv().unwrap(), "acme:/callback?code=c&state=s");
        assert!(!w.take("acme:/callback?code=c"));
    }

    #[tokio::test]
    async fn loopback_answers_only_its_path_and_returns_the_callback() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}/cb");
        let caught = tokio::spawn({
            let base = base.clone();
            async move { catch(l, "/cb", &base).await }
        });
        for target in ["/favicon.ico", "/cb?code=c&state=s"] {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            s.write_all(format!("GET {target} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).await.unwrap();
            assert_eq!(
                out.contains("200 OK"),
                target.starts_with("/cb"),
                "{target}: {out}"
            );
        }
        assert_eq!(
            caught.await.unwrap().unwrap(),
            format!("{base}?code=c&state=s")
        );
    }
}
