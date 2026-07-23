import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Relative base so this single canonical bundle works from either the Community
// or authenticated Active Defence embedded static root.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "./",
  build: { outDir: "dist", emptyOutDir: true },
  // In `npm run dev`, proxy the JSON API to a locally-running dashboard binary
  // (`innerwarden dashboard`), so `fetch("api/...")` works from the Vite dev server.
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:8788", changeOrigin: true },
    },
  },
});
