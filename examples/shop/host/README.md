A Vite + React app using the shop's components as an npm package. `configure({ navigate })`
routes doxa's `<Link>`s through react-router, `invalidated` marks react-query's queries stale
after a doxa mutation, and `invalidate(["Widget"])` does the reverse.

```sh
doxa build --lib -p shop-web                 # writes target/doxa/lib
cargo run -p shop-server                     # the API, on :3000
cd host && npm install && npm run dev
```
