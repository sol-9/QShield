import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

// The SDK is consumed from source so the app always matches the repository's SDK.
export default defineConfig({
  resolve: {
    alias: { '@qshield/sdk': fileURLToPath(new URL('../../sdk/typescript/src/index.ts', import.meta.url)) },
  },
  build: { target: 'es2022', sourcemap: true },
  server: { port: 5173 },
});
