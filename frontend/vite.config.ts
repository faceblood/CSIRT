import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/** Dev server port: `VITE_DEV_PORT`, else `PORT`, else Vite default 5173. CLI `--port` still overrides. */
function devPort(): number {
  const raw = process.env.VITE_DEV_PORT ?? process.env.PORT;
  if (raw === undefined || raw === "") return 5173;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return 5173;
  return n;
}

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: devPort(),
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
});
