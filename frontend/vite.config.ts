import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

// vite.config.ts runs under Node, where process.env is available at config
// load time. Declare just the key we need so strict TS is satisfied without
// pulling @types/node into the browser bundle.
declare const process: { env: { VITE_PROXY_TARGET?: string } };

// The FastAPI backend serves app/static/index.html at "/" — so we build a
// fully self-contained HTML file (all JS + CSS inlined) into app/static.
// This keeps the existing Vercel routing (everything -> api/index.py) working
// with no backend or deployment changes.
export default defineConfig({
  plugins: [react(), viteSingleFile()],
  base: "./",
  build: {
    outDir: "../app/static",
    emptyOutDir: true,
    assetsInlineLimit: 100_000_000,
  },
  server: {
    port: 5173,
    // In dev, the browser talks to Vite and Vite forwards API calls to the
    // FastAPI backend, so everything stays same-origin (and the backend's
    // localhost-only CORS allow list is never an issue).
    // Override the default (localhost:8000) with VITE_PROXY_TARGET when the
    // backend runs on another port, e.g. `VITE_PROXY_TARGET=http://127.0.0.1:8001`.
    proxy: {
      "/api": process.env.VITE_PROXY_TARGET || "http://localhost:8000",
    },
  },
});