import { defineConfig } from 'vitest/config';

// Vitest runs the MCP tests: it handles the ESM MCP SDK natively (Jest's CJS
// runtime cannot import it). The tests import the built server from dist/, so
// run `npm run build` first (the test:mcp script does this).
export default defineConfig({
  test: {
    include: ['tests/mcp/**/*.test.ts'],
    environment: 'node',
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
