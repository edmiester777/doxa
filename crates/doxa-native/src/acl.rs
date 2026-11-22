//! The one capability the main window runs with, built at startup instead of from JSON files.

use serde_json::{json, Value};
use tauri::ipc::CapabilityBuilder;

use crate::window::MAIN;

/// What every doxa app grants its page. Some plugin defaults are empty (clipboard) or lack the
/// scope a call needs (opener), so each is named.
pub(crate) const PERMISSIONS: &[&str] = &[
    "core:default",
    "doxa:default",
    "dialog:allow-open",
    "dialog:allow-save",
    "dialog:allow-message",
    "dialog:allow-ask",
    "dialog:allow-confirm",
    "notification:default",
    "clipboard-manager:allow-read-text",
    "clipboard-manager:allow-write-text",
    "opener:allow-open-url",
    "opener:allow-default-urls",
    "deep-link:default",
];

/// A permission and, for a scoped one, what it allows.
#[derive(Debug, Clone)]
pub(crate) enum Grant {
    Plain(String),
    Scoped(String, Vec<Value>),
}

/// The main window's capability. `remote` is the local server's origin, which Tauri treats as
/// remote; `commands` are the app's, each granted as `allow-<command>`.
pub(crate) fn capability(
    remote: Option<&str>,
    commands: &[String],
    extra: &[Grant],
) -> CapabilityBuilder {
    let mut cap = CapabilityBuilder::new("doxa").window(MAIN).local(true);
    if let Some(origin) = remote {
        cap = cap.remote(format!("{}/*", origin.trim_end_matches('/')));
    }
    for p in PERMISSIONS {
        cap = cap.permission(*p);
    }
    for c in commands {
        cap = cap.permission(format!("allow-{}", c.replace('_', "-")));
    }
    for g in extra {
        cap = match g {
            Grant::Plain(p) => cap.permission(p.clone()),
            Grant::Scoped(p, allow) => {
                cap.permission_scoped(p.clone(), allow.clone(), Vec::<Value>::new())
            }
        };
    }
    cap
}

/// The opener's scope entry allowing paths under `glob`.
pub(crate) fn open_path(glob: &str) -> Grant {
    Grant::Scoped(
        "opener:allow-open-path".into(),
        vec![json!({ "path": glob })],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tauri::ipc::RuntimeCapability;

    fn built(cap: CapabilityBuilder) -> Value {
        use tauri::utils::acl::capability::CapabilityFile;
        match cap.build() {
            CapabilityFile::Capability(c) => serde_json::to_value(c).unwrap(),
            _ => panic!("the builder makes one capability"),
        }
    }

    #[test]
    fn the_local_server_is_a_remote_origin_and_commands_are_slugged() {
        let c = built(capability(
            Some("http://127.0.0.1:4000/"),
            &["export_pdf".into()],
            &[
                Grant::Plain("store:default".into()),
                open_path("$DOCUMENT/**"),
            ],
        ));
        assert_eq!(c["remote"]["urls"], json!(["http://127.0.0.1:4000/*"]));
        assert_eq!(c["windows"], json!([MAIN]));
        let perms = c["permissions"].to_string();
        for p in PERMISSIONS {
            assert!(perms.contains(p), "{p} in {perms}");
        }
        assert!(perms.contains("allow-export-pdf"), "{perms}");
        assert!(perms.contains("store:default"), "{perms}");
        assert!(perms.contains("\"path\":\"$DOCUMENT/**\""), "{perms}");
    }

    #[test]
    fn remote_and_dev_pages_get_no_remote_origin() {
        let c = built(capability(None, &[], &[]));
        assert!(c.get("remote").is_none_or(Value::is_null), "{c}");
    }
}
