# Deploying

Two shapes. **One binary**: the server with the web app compiled into it, so you copy one file and run it. **Static files**: the web app as a folder for any static host, with the API wherever you like.

## One binary

Give the server an `embed` feature and mount the app as a SPA:

```toml
# server/Cargo.toml
[features]
embed = ["doxa/embed"]
```

```rust
use doxa::{dist, MountSpaExt, Spa};

let app = shop_server::app(state).mount_spa(Spa::auto(dist!()));
```

```sh
doxa build --release -p shop-web
./target/release/shop-server
```

`doxa build` compiles the web crate to wasm, runs `wasm-opt` when it's on your `PATH`, bundles the JS and CSS with content hashes, precompresses everything with brotli and gzip, and builds the server with the result inside. `Spa` serves the hashed files with long cache lifetimes and `index.html` for every page route.

Keep the binary small by setting budgets: `wasm_budget_kb` and `chunk_budget_kb` under `[package.metadata.doxa]` fail a release build that grows past them.

## Static files

```sh
doxa build --release -p site --out public
```

`--out` writes plain files with no server build: the hashed assets, `index.html`, and a copy of it as `404.html`, so a static host serves every page route. Point Netlify, Cloudflare Pages, S3 or anything else at the folder.

## Under a path

Serving from `https://you.github.io/my-repo/` rather than a domain root? Set the base:

```toml
[package.metadata.doxa]
base = "/my-repo/"
```

or pass `--base /my-repo/` to `doxa build` or `doxa gallery`. Asset URLs, stylesheet `url()`s, `<Link>` hrefs and history all carry it, and route templates stay `/`-rooted. For a plain `<a>` to a static file beside the app, `doxa::ui::href(&"/gallery/".into())` adds the base.

## GitHub Pages

This site is deployed that way. The workflow builds the site, the shop's story gallery and the shop's API reference into one folder:

```yaml
- run: cargo run -q -p doxa-cli -- build --release -p site --out _site --base /doxa/
- run: cargo run -q -p doxa-cli -- gallery -p shop-web --out _site/gallery --base /doxa/gallery/
- run: cargo run -q -p shop-server --bin export-docs -- --base /doxa/api/ _site/api
- uses: actions/upload-pages-artifact@v3
  with: { path: _site }
- uses: actions/deploy-pages@v4
```

The [whole workflow](../../../.github/workflows/pages.yml) is in the repo, free for public projects.

## Runtime config

`services.json` sits beside `index.html` and maps each API crate to its base URL. Edit it per environment and the same build talks to staging or production.
