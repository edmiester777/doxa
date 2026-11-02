// A React app embedding the widgets components; `doxa build --lib` writes the package first.
import { defineConfig } from "vite";

export default defineConfig({
  esbuild: { jsx: "automatic" },
  // The package's wasm is fetched at run time, not imported.
  optimizeDeps: { exclude: ["@widgets/kit"] },
  // `file:` links the package from target/, where React isn't installed.
  resolve: { dedupe: ["react", "react-dom"] },
  server: {
    proxy: { "/api": "http://127.0.0.1:3000" },
    fs: { allow: [".", "../../../target/doxa/lib"] },
  },
});
