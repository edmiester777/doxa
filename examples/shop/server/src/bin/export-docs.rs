//! Writes the shop's API reference as static files: `export-docs [--base /api/] <dir>`.

use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use doxa::{MountDocsExt, MountOpts};
use tower::ServiceExt;

#[tokio::main]
async fn main() {
    let (mut base, mut out) = (String::from("/"), None);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--base" => base = args.next().expect("--base takes a path"),
            _ => out = Some(PathBuf::from(arg)),
        }
    }
    let out = out.expect("usage: export-docs [--base /api/] <dir>");
    let base = match base.trim_matches('/') {
        "" => "/".to_owned(),
        inner => format!("/{inner}/"),
    };
    let spec = format!("{base}openapi.json");
    let opts = MountOpts::default().spec_path(&spec).ui_path(&base);
    let router = axum::Router::new().mount_docs(shop_server::api_doc(), opts);

    std::fs::create_dir_all(&out).unwrap();
    for (path, file) in [(&base, "index.html"), (&spec, "openapi.json")] {
        let req = Request::get(path.as_str()).body(Body::empty()).unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "GET {path}");
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        std::fs::write(out.join(file), body).unwrap();
    }
    eprintln!("wrote {}", out.display());
}
