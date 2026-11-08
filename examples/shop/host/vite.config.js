// A React app embedding the widgets components; `doxa build --lib` writes the package first.
import { defineConfig } from "vite";

export default defineConfig({
  esbuild: { jsx: "automatic" },
  // The package's wasm is fetched at run time, not imported.
  optimizeDeps: { exclude: ["@shop/kit"] },
  // `file:` links the package from target/, where React isn't installed.
  resolve: { dedupe: ["react", "react-dom"] },
  server: {
    // The demo server reads the caller's role from `x-role` in place of a token.
    proxy: { "/api": { target: "http://127.0.0.1:3000", headers: { "x-role": "editor" } } },
    fs: { allow: [".", "../../../target/doxa/lib"] },
  },
});
