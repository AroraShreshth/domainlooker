import { createRequire } from 'module';

// Single source of truth for the version: read it from package.json at runtime
// so a `npm version` bump updates the CLI, MCP server, and --version at once.
const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { version: string };

export const VERSION: string = pkg.version;
