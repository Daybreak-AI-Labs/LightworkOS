import { svelte, vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vitest/config';

export default defineConfig(({ mode }) => ({
  // vitePreprocess transpiles <script lang="ts"> (TS -> JS via esbuild).
  // Without it the Svelte compiler can't parse any TypeScript in a
  // component -- which is why the build failed on the first type-import.
  plugins: [svelte({ preprocess: vitePreprocess() })],
  // Vitest runs under Node, whose default export conditions select Svelte's
  // server build. Component behavior tests need the same browser build the
  // Tauri webview executes.
  resolve: mode === 'test' ? { conditions: ['browser'] } : undefined,
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
  },
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
  envPrefix: ['VITE_', 'TAURI_'],
}));
