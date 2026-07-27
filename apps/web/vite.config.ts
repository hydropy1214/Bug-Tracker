import path from 'path';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

import runtimeErrorOverlay from '@replit/vite-plugin-runtime-error-modal';

// PORT and BASE_PATH are injected by the Replit artifact system.
// Fall back to sensible defaults so Vite never crashes on a cold start.
const rawPort = process.env.PORT ?? '5173';
const port = Number(rawPort);
if (Number.isNaN(port) || port <= 0) {
  console.warn(`[vite] Invalid PORT "${rawPort}", falling back to 5173`);
}
const resolvedPort = Number.isNaN(port) || port <= 0 ? 5173 : port;

const basePath = process.env.BASE_PATH ?? '/';

export default defineConfig({
  base: basePath ?? '/',
  plugins: [
    react(),
    tailwindcss(),
    runtimeErrorOverlay(),
    ...(process.env.NODE_ENV !== 'production' &&
    process.env.REPL_ID !== undefined
      ? [
          await import('@replit/vite-plugin-cartographer').then((m) =>
            m.cartographer({
              root: path.resolve(import.meta.dirname, '..'),
            }),
          ),
          await import('@replit/vite-plugin-dev-banner').then((m) =>
            m.devBanner(),
          ),
        ]
      : []),
  ],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, 'src'),
    },
    dedupe: ['react', 'react-dom'],
  },
  root: path.resolve(import.meta.dirname),
  build: {
    outDir: path.resolve(import.meta.dirname, 'dist/public'),
    emptyOutDir: true,
  },
  server: {
    port: resolvedPort,
    strictPort: true,
    host: '0.0.0.0',
    allowedHosts: true,
    fs: {
      strict: true,
    },
    proxy: {
      '/api': {
        target: `http://localhost:${process.env.API_PORT ?? 8080}`,
        changeOrigin: true,
      },
    },
  },
  preview: {
    port: resolvedPort,
    host: '0.0.0.0',
    allowedHosts: true,
  },
});
