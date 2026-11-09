# shop

A small widget shop, written once and compiled for both halves.

| Crate | What it is |
|---|---|
| `api` | Every route with its DTOs and errors, built for the server and the browser. `src/server/` holds the stores, guards and layers only the server compiles, and the binary serves it all. |
| `web` | The pages, `#[story]`s, React and npm interop, and the `--lib` kit `host/` embeds. |

```sh
cargo test -p shop-api -p shop-web                      # calls and pages, against the real router
doxa dev -p shop-web                                    # rebuild on change, at http://127.0.0.1:3000
doxa gallery -p shop-web                                # the stories, at http://127.0.0.1:4710
doxa build -p shop-web && ./target/debug/shop-api       # the server with the app embedded
cargo run -p shop-api --bin export-docs -- out/api      # the API reference as static files
```

The server reads the caller's role from an `x-role` header in place of a real token:
`viewer` reads, `editor` renames widgets, `clerk` places and cancels orders, and `admin` does
anything. A browser that sends none is an `admin`.
