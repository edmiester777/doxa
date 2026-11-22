//! Cargo passes a plugin's `DEP_*` vars only to direct dependents, so the app's `tauri-build`
//! wouldn't see these plugins. Each one is forwarded as `fwd<n>=<KEY>=<value>`, a name
//! `tauri-build` doesn't scan, and `doxa_role::client()` restores it.

const SUFFIXES: &[&str] = &[
    "_PERMISSION_FILES_PATH",
    "_GLOBAL_SCOPE_SCHEMA_PATH",
    "_ANDROID_LIBRARY_PATH",
];

fn main() {
    let mut vars: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| {
            // `tauri`'s own reach the app directly; it depends on `tauri` too.
            k.starts_with("DEP_TAURI_PLUGIN_") && SUFFIXES.iter().any(|s| k.ends_with(s))
        })
        .collect();
    vars.sort();
    for (n, (k, v)) in vars.iter().enumerate() {
        println!("cargo::metadata=fwd{n}={k}={v}");
        println!("cargo::rerun-if-env-changed={k}");
    }
    println!("cargo::rerun-if-changed=build.rs");
}
