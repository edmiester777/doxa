# site

doxa's own site, built with doxa and published to GitHub Pages by `.github/workflows/pages.yml`.

- `guides/*.md` are the guides. They read fine on GitHub, and `build.rs` compiles them into the site.
- `src/` is the landing page and the guide pages. `ts/highlight.js` is highlight.js, bound with `#[npm]`.
- The version shown is the workspace's, from `Cargo.toml`.

```sh
doxa build --release -p site --out _site --base /doxa/
```

The published site also carries the shop's story gallery at `/gallery/` and its API reference at `/api/`. The workflow builds each into the same folder.
