# Contributing to DOMAINLOOKER

Thank you for your interest in contributing to DOMAINLOOKER! We welcome contributions from the community.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/domainlooker.git
   cd domainlooker
   ```
3. **Install dependencies**:
   ```bash
   npm install
   ```
4. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Requirements
- Node.js 16.0.0 or higher
- npm 7.0.0 or higher

### Available Scripts
```bash
npm run build       # Compile TypeScript
npm run dev         # Run in development mode
npm run test        # Run all tests (Jest units/integration + Vitest MCP tests)
npm run test:core   # Run core functionality tests
npm run test:mcp    # Run only the MCP server tests (Vitest, in-memory + stdio)
npm run test:watch  # Run tests in watch mode
npm run typecheck   # Type checking
```

### Project Structure
```
src/
├── index.ts              # CLI entry point
├── domain-inspector.ts   # Main orchestration class
├── services/            # Core services
│   ├── whois.ts         # WHOIS data collection
│   ├── dns.ts           # DNS record analysis
│   ├── ssl.ts           # SSL certificate inspection
│   ├── network.ts       # Network scanning
│   ├── subdomain.ts     # Subdomain discovery
│   ├── csv-export.ts    # CSV export functionality
│   └── json-export.ts   # JSON export functionality
├── types/               # TypeScript type definitions
└── ui/                  # Terminal UI components
```

## How to Contribute

### Reporting Issues
- Use the GitHub issue tracker
- Include steps to reproduce the problem
- Provide example domains (use example.com, test.com, etc.)
- Include your Node.js version and operating system

### Submitting Changes

1. **Write tests** for new functionality
2. **Ensure all tests pass**:
   ```bash
   npm run test
   npm run build
   ```
3. **Follow the existing code style**
4. **Update documentation** if needed
5. **Commit your changes** with descriptive messages
6. **Push to your fork** and submit a pull request

### Pull Request Guidelines

- **One feature per PR** - keep changes focused
- **Write clear commit messages** following the existing pattern
- **Add tests** for new functionality
- **Update README** if adding new features or changing usage
- **Ensure CI passes** - all tests must pass on all platforms

### Code Style

- Use TypeScript strict mode
- Follow existing naming conventions
- Add JSDoc comments for public APIs
- Use meaningful variable and function names
- Keep functions focused and single-purpose

### Testing

We use Jest for testing:
- **Unit tests** for individual services (`tests/unit/`)
- **Integration tests** for CLI functionality (`tests/integration/`)
- **Mock external services** to avoid real network calls
- **Test error conditions** and edge cases

Example test structure:
```typescript
describe('ServiceName', () => {
  it('should handle valid input', async () => {
    // Test implementation
  });

  it('should handle invalid input gracefully', async () => {
    // Error handling test
  });
});
```

## Areas for Contribution

### Priority Areas
- **New domain analysis features** (security headers, DNS security, etc.)
- **Additional export formats** (XML, YAML, etc.)
- **Performance optimizations** for large domain sets
- **Enhanced subdomain discovery** techniques
- **Better error handling** and user feedback

### Documentation
- **Usage examples** for specific use cases
- **API documentation** for JSON export format
- **Security best practices** guide
- **Integration examples** with other tools

### Testing
- **Edge case testing** for various domain configurations
- **Performance testing** for large domain sets
- **Cross-platform testing** improvements

## Security Considerations

- **Never commit** API keys, credentials, or sensitive data
- **Respect rate limits** when adding new external service integrations
- **Handle errors gracefully** to avoid exposing system information
- **Validate all inputs** to prevent injection attacks
- **Use HTTPS** for all external API calls

## Release Process

Releases are automated through GitHub Actions:
1. Update version in `package.json`
2. Create a pull request with changes
3. After merge, tag the release
4. GitHub Actions will automatically publish to npm

## Docs site

The docs page (`docs/index.html`) is hosted on Cloudflare Pages (project
`domainlooker`) at <https://domainlooker.shreshtharora.com>, with the default
alias <https://domainlooker.pages.dev>.

Deploy manually with an authenticated wrangler:

```bash
wrangler pages deploy docs --project-name=domainlooker --branch=main
```

For hands-off deploys, connect the repo in the Cloudflare dashboard
(Workers & Pages → Create → Pages → Connect to Git) with **build command:**
none and **build output directory:** `docs` — Cloudflare then redeploys on
every push to `main`.

## Need Help?

- **Check existing issues** on GitHub
- **Read the documentation** in the `docs/` directory
- **Look at test files** for usage examples
- **Open a discussion** for questions about architecture or design

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow the Golden Rule

Thank you for contributing to domainlooker!