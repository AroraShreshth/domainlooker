export default {
  preset: 'ts-jest/presets/default-esm',
  extensionsToTreatAsEsm: ['.ts'],
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: [
    '**/__tests__/**/*.ts',
    '**/?(*.)+(spec|test).ts'
  ],
  // The MCP tests import the ESM MCP SDK, which Jest's CJS runtime cannot load;
  // they run under Vitest instead (see vitest.config.ts / `npm run test:mcp`).
  testPathIgnorePatterns: ['/node_modules/', '<rootDir>/tests/mcp/'],
  transform: {
    '^.+\\.ts$': ['ts-jest', { useESM: true }],
  },
  transformIgnorePatterns: [
    'node_modules/(?!(chalk|ora|boxen|figlet|gradient-string|inquirer|cli-table3)/)'
  ],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/index.ts' // Exclude CLI entry point from coverage
  ],
  coverageDirectory: 'coverage',
  coverageReporters: [
    'text',
    'lcov',
    'html'
  ],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  testTimeout: 30000, // 30 second timeout for network operations
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1'
  }
};