# shop

A small widget shop, written once and compiled for both halves.

| Crate | What it is |
|---|---|
| `api` | Every route as a declaration, with its DTOs and errors. Builds for the server and the browser. |
| `server` | The axum app: each declaration `#[implements]`-ed, guarded by role, documented in OpenAPI. |
| `web` | The pages, `#[story]`s, React and npm interop, and the `--lib` kit `host/` embeds. |

```sh
cargo test -p shop-api -p shop-server -p shop-web       # calls and pages, against the real router
doxa dev -p shop-web                                    # rebuild on change, at http://127.0.0.1:3000
doxa gallery -p shop-web                                # the stories, at http://127.0.0.1:4710
doxa build -p shop-web && ./target/debug/shop-server    # the server with the app embedded
cargo run -p shop-server --bin export-docs -- out/api   # the API reference as static files
```

The server reads the caller's role from an `x-role` header in place of a real token:
`viewer` reads, `editor` renames widgets, `clerk` places and cancels orders, and `admin` does
anything. A browser that sends none is an `admin`.
