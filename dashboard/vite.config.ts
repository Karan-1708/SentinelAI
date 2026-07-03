import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// When running inside Docker (compose sets `INSIDE_DOCKER=1`) we bind to
// 0.0.0.0 so the container's forwarded port is reachable. Outside Docker
// we stay on 127.0.0.1 — the dev server should never be exposed to a LAN
// while HMR is active (arbitrary WS -> code execution).
const insideDocker = process.env.INSIDE_DOCKER === '1'

export default defineConfig({
  plugins: [react()],
  build: {
    // Never ship source maps to production — leaks module structure and
    // makes CVE reconnaissance trivial.
    sourcemap: false,
    // Refuse the build if a dependency ends up over ~500KB minified — forces
    // review of new dashboard deps.
    chunkSizeWarningLimit: 500,
  },
  server: {
    host: insideDocker ? '0.0.0.0' : '127.0.0.1',
    port: 3000,
    strictPort: true,
    watch: {
      usePolling: insideDocker,
      interval: 300,
    },
    proxy: {
      '/api': {
        target: process.env.API_TARGET || 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
      '/ws': {
        target: process.env.WS_TARGET || 'ws://localhost:8000',
        ws: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: [],
  },
})
