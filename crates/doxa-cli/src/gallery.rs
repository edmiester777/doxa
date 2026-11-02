//! `doxa gallery`: build the `#[story]` gallery and serve it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use doxa_build::{BuildOptions, Pipeline};

type DynError = Box<dyn std::error::Error>;

/// Build the gallery, then serve it on `port` until interrupted.
pub async fn run(package: Option<String>, port: u16, locked: bool) -> Result<(), DynError> {
    let mut pipeline = Pipeline::new(
        &std::env::current_dir()?,
        BuildOptions {
            package,
            locked,
            gallery: true,
            ..BuildOptions::default()
        },
    )?;
    pipeline.build()?;
    let dir = Arc::new(pipeline.dist_dir());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("[doxa] stories at http://127.0.0.1:{port}/");
    let app = Router::new().fallback(file).with_state(dir);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn file(State(dir): State<Arc<PathBuf>>, uri: Uri) -> Response {
    let rel = uri.path().trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    match resolve(&dir, rel) {
        Some(path) => match tokio::fs::read(&path).await {
            Ok(bytes) => ([(header::CONTENT_TYPE, content_type(&path))], bytes).into_response(),
            Err(_) => StatusCode::NOT_FOUND.into_response(),
        },
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `rel` under `dir`, refusing anything that climbs out of it.
fn resolve(dir: &Path, rel: &str) -> Option<PathBuf> {
    let path = Path::new(rel);
    path.components()
        .all(|c| matches!(c, std::path::Component::Normal(_)))
        .then(|| dir.join(path))
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript",
        Some("wasm") => "application/wasm",
        Some("css") => "text/css",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_files_under_the_gallery_are_served() {
        let dir = Path::new("/g");
        assert_eq!(resolve(dir, "app.js"), Some(PathBuf::from("/g/app.js")));
        assert_eq!(
            resolve(dir, "chunks/a.js"),
            Some(PathBuf::from("/g/chunks/a.js"))
        );
        assert_eq!(resolve(dir, "../secret"), None);
        assert_eq!(resolve(dir, "/etc/passwd"), None);
        assert_eq!(content_type(Path::new("a.wasm")), "application/wasm");
    }
}
