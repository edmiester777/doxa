//! What every native target has: dialogs, notifications, the clipboard, URLs and shell events.

use std::cell::RefCell;
use std::rc::Rc;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;

use super::Native;
use crate::browser::hold;
use crate::hooks::{effect, latest};
use doxa_client::native::{invoke, listen};

/// Calls `f` with each payload of the shell's `event` while this component is mounted.
#[track_caller]
pub fn on<T: DeserializeOwned + 'static>(event: &str, f: impl Fn(T) + 'static) {
    let f = latest(f);
    effect(&event.to_owned(), async move |event: &String| {
        hold(listen(event, move |t: T| {
            f.with(|f| f(t));
        }))
        .await
    });
}

/// Calls `f` with the URLs the app is opened with (its schemes and app links) while this
/// component is mounted, starting with those that launched it.
#[track_caller]
pub fn on_open_url(f: impl Fn(Vec<String>) + 'static) {
    let f = latest(f);
    effect((), async move |_: &()| {
        // What the event brings while the take is in flight; the shell held those too.
        let heard = Rc::new(RefCell::new(Some(Vec::<String>::new())));
        let seen = heard.clone();
        let listening = listen("doxa://open-url", move |urls: Vec<String>| {
            if let Some(s) = seen.borrow_mut().as_mut() {
                s.extend(urls.iter().cloned());
            }
            f.with(|f| f(urls));
        });
        let mut waiting: Vec<String> = invoke("plugin:doxa|take_open_urls", &json!({})).await?;
        let heard = heard.borrow_mut().take().unwrap_or_default();
        waiting.retain(|u| !heard.contains(u));
        if !waiting.is_empty() {
            f.with(|f| f(waiting));
        }
        hold(listening).await
    });
}

/// Opens `url` in the system's handler for it: the browser for `https`.
pub async fn open_url(url: &str) -> Result<(), Native> {
    invoke("plugin:opener|open_url", &json!({ "url": url })).await
}

/// A system notification.
#[derive(Debug, Clone, Serialize)]
pub struct Notification {
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
}

impl Notification {
    pub fn new(title: impl Into<String>) -> Self {
        Notification {
            title: title.into(),
            body: None,
        }
    }

    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }
}

/// Shows `n`, asking for permission first where the platform wants it.
pub async fn notify(n: Notification) -> Result<(), Native> {
    let granted: Option<bool> =
        invoke("plugin:notification|is_permission_granted", &json!({})).await?;
    if granted != Some(true) {
        let answer: String = invoke("plugin:notification|request_permission", &json!({})).await?;
        if answer != "granted" {
            return Err(Native::Command("notifications aren't allowed".into()));
        }
    }
    invoke("plugin:notification|notify", &json!({ "options": n })).await
}

pub mod clipboard {
    use super::*;

    pub async fn read_text() -> Result<String, Native> {
        invoke("plugin:clipboard-manager|read_text", &json!({})).await
    }

    pub async fn write_text(text: &str) -> Result<(), Native> {
        invoke(
            "plugin:clipboard-manager|write_text",
            &json!({ "text": text }),
        )
        .await
    }
}

pub mod dialog {
    //! The system's file pickers and message boxes.

    use super::*;

    #[derive(Debug, Clone, Serialize)]
    struct Filter {
        name: String,
        extensions: Vec<String>,
    }

    /// An open-file (or folder) picker.
    #[derive(Debug, Clone, Default, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Open {
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        filters: Vec<Filter>,
        multiple: bool,
        directory: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        default_path: Option<String>,
    }

    impl Open {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn title(mut self, title: impl Into<String>) -> Self {
            self.title = Some(title.into());
            self
        }

        /// Only files with these extensions, without the dot, listed as `name`.
        pub fn filter(mut self, name: impl Into<String>, extensions: &[&str]) -> Self {
            self.filters.push(Filter {
                name: name.into(),
                extensions: extensions.iter().map(|e| (*e).to_owned()).collect(),
            });
            self
        }

        pub fn multiple(mut self) -> Self {
            self.multiple = true;
            self
        }

        /// Pick folders instead of files.
        pub fn directory(mut self) -> Self {
            self.directory = true;
            self
        }

        pub fn starting_at(mut self, path: impl Into<String>) -> Self {
            self.default_path = Some(path.into());
            self
        }
    }

    /// The paths picked; empty when cancelled.
    pub async fn open(o: Open) -> Result<Vec<String>, Native> {
        let picked: serde_json::Value =
            invoke("plugin:dialog|open", &json!({ "options": o })).await?;
        Ok(paths(picked))
    }

    fn paths(v: serde_json::Value) -> Vec<String> {
        match v {
            serde_json::Value::String(s) => vec![s],
            serde_json::Value::Array(a) => a
                .into_iter()
                .filter_map(|p| p.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// A save-file picker.
    #[derive(Debug, Clone, Default, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Save {
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        filters: Vec<Filter>,
        #[serde(skip_serializing_if = "Option::is_none")]
        default_path: Option<String>,
    }

    impl Save {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn title(mut self, title: impl Into<String>) -> Self {
            self.title = Some(title.into());
            self
        }

        pub fn filter(mut self, name: impl Into<String>, extensions: &[&str]) -> Self {
            self.filters.push(Filter {
                name: name.into(),
                extensions: extensions.iter().map(|e| (*e).to_owned()).collect(),
            });
            self
        }

        /// The suggested file name, or a path to start at.
        pub fn name(mut self, name: impl Into<String>) -> Self {
            self.default_path = Some(name.into());
            self
        }
    }

    /// The path chosen; `None` when cancelled.
    pub async fn save(s: Save) -> Result<Option<String>, Native> {
        invoke("plugin:dialog|save", &json!({ "options": s })).await
    }

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "lowercase")]
    pub enum Kind {
        #[default]
        Info,
        Warning,
        Error,
    }

    /// A message box.
    #[derive(Debug, Clone, Serialize)]
    pub struct Message {
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        kind: Kind,
    }

    impl Message {
        pub fn new(message: impl Into<String>) -> Self {
            Message {
                message: message.into(),
                title: None,
                kind: Kind::Info,
            }
        }

        pub fn title(mut self, title: impl Into<String>) -> Self {
            self.title = Some(title.into());
            self
        }

        pub fn kind(mut self, kind: Kind) -> Self {
            self.kind = kind;
            self
        }
    }

    /// Shows `m` with an OK button, until dismissed.
    pub async fn message(m: Message) -> Result<(), Native> {
        let _: serde_json::Value = invoke("plugin:dialog|message", &with_buttons(&m, "Ok")).await?;
        Ok(())
    }

    /// Shows `m` with OK and Cancel; `true` for OK.
    pub async fn confirm(m: Message) -> Result<bool, Native> {
        let pressed: String =
            invoke("plugin:dialog|message", &with_buttons(&m, "OkCancel")).await?;
        Ok(pressed == "Ok")
    }

    fn with_buttons(m: &Message, buttons: &str) -> serde_json::Value {
        let mut v = json!(m);
        v["buttons"] = buttons.into();
        v
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn options_serialize_as_the_dialog_plugin_reads_them() {
            let o = Open::new()
                .title("Pick")
                .filter("Images", &["png"])
                .multiple();
            assert_eq!(
                json!(o),
                json!({ "title": "Pick", "filters": [{ "name": "Images", "extensions": ["png"] }],
                        "multiple": true, "directory": false })
            );
            assert_eq!(json!(Save::new().name("a.pdf"))["defaultPath"], "a.pdf");
            let m = with_buttons(&Message::new("Sure?").kind(Kind::Warning), "OkCancel");
            assert_eq!(
                m,
                json!({ "message": "Sure?", "kind": "warning", "buttons": "OkCancel" })
            );
        }

        #[test]
        fn a_pick_is_a_list_of_paths_whatever_the_plugin_answers() {
            assert_eq!(paths(json!("/a")), ["/a"]);
            assert_eq!(paths(json!(["/a", "/b"])), ["/a", "/b"]);
            assert!(paths(json!(null)).is_empty());
        }
    }
}
