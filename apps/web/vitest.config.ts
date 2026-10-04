import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
export default defineConfig({
  resolve: { alias: { '@qshield/sdk': fileURLToPath(new URL('../../sdk/typescript/src/index.ts', import.meta.url)) } },
  test: { include: ['src/**/*.test.ts'] },
});
