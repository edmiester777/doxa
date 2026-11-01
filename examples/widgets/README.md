# widgets

One app, written once and compiled for both halves.

| Crate | What it is |
|---|---|
| `api` | The routes, DTOs and errors. The server's view of the shared source. |
| `client` | The same source (`[lib] path = "../api/src/lib.rs"`) with `doxa_role::client()` in `build.rs`: every route becomes a typed call. |
| `server` | The axum app: the routes behind a stand-in auth layer, with `ETagLayer`. |
| `web` | The pages (`doxa::ui`), mounted in the browser by `#[doxa::start]`. |

```sh
cargo test -p widgets-client -p widgets-web     # client calls and pages, against the real router, natively
cargo check -p widgets-web --target wasm32-unknown-unknown
```
