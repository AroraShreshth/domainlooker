import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { fileURLToPath } from 'url';
import * as path from 'path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

/**
 * One real-transport smoke test: launch the actual `domainlooker mcp` binary and
 * drive it over stdio with the real SDK client. This proves the shipped process
 * speaks the protocol and never corrupts the stdout JSON-RPC stream. Deeper
 * behavior is covered deterministically by the in-memory suite.
 */
const cliPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../dist/index.js');

describe('MCP server (real stdio transport)', () => {
  let client: Client;
  let transport: StdioClientTransport;

  beforeAll(async () => {
    transport = new StdioClientTransport({ command: 'node', args: [cliPath, 'mcp'] });
    client = new Client({ name: 'stdio-smoke', version: '1.0.0' });
    await client.connect(transport);
  }, 30_000);

  afterAll(async () => {
    await client?.close();
  });

  it('reports its server info', () => {
    const info = client.getServerVersion();
    expect(info?.name).toBe('domainlooker');
  });

  it('lists the six tools over real stdio', async () => {
    const { tools } = await client.listTools();
    expect(tools.map(t => t.name).sort()).toEqual(
      ['dns_records', 'find_subdomains', 'inspect_domain', 'scan_ports', 'ssl_certificate', 'whois_lookup'],
    );
  });

  it('blocks an IP-literal target through the real guard (no network needed)', async () => {
    const result: any = await client.callTool({ name: 'scan_ports', arguments: { domain: '127.0.0.1' } });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/IP address/i);
  });
});
