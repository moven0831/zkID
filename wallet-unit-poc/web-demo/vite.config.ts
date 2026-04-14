import { defineConfig } from "vite";

export default defineConfig({
  // BigInt support requires ES2020+
  build: {
    target: "es2020",
  },
  optimizeDeps: {
    esbuildOptions: {
      target: "es2020",
    },
  },
  // Emit Web Workers as ES modules so the proving worker can use dynamic
  // import() for the Spartan2 WASM JS glue and the Circom witness builder.
  worker: {
    format: "es",
  },
  server: {
    headers: {
      // Required for WebAssembly.Module() in initSync()
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "credentialless",
    },
    // Allow serving files from parent directories (openac-sdk source)
    fs: {
      allow: [".."],
    },
  },
});
