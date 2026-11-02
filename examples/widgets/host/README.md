A Vite + React app using the widgets components as an npm package.

```sh
cd examples/widgets && doxa build --lib     # writes target/doxa/lib
cargo run -p widgets-server                  # the API, on :3000
cd host && npm install && npm run dev
```
