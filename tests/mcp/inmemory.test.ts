import { describe, it, expect } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
// Import the BUILT server: it pulls in the ESM MCP SDK, which Vitest loads natively.
import { createServer, type ServerDeps, type CollectorLike } from '../../dist/mcp/server.js';

/**
 * Best-practice MCP unit test: link a real SDK Client to the McpServer through
 * InMemoryTransport.createLinkedPair() — full protocol stack, no subprocess, no
 * network. The DomainCollector and target guard are injected as deterministic
 * fakes so results depend only on our code, not on live DNS/WHOIS/TLS.
 */

interface FakeCollector extends CollectorLike {
  collectCalls: number;
}

function makeCollector(overrides: Partial<CollectorLike> = {}): FakeCollector {
  const fake: FakeCollector = {
    collectCalls: 0,
    async collect(domain, opts) {
      fake.collectCalls++;
      return {
        domain,
        whois: { registrar: 'Fake Registrar Inc.', registrationDate: '2000-01-01T00:00:00Z' },
        dns: { a: ['93.184.216.34'], ns: ['a.iana-servers.net'] },
        ssl: { subject: `CN=${domain}`, issuer: 'CN=Fake CA', daysUntilExpiry: 100 },
        ...(opts?.quick ? {} : { network: { openPorts: [80, 443], services: [{ port: 80, protocol: 'TCP', service: 'HTTP' }] } }),
      };
    },
    async whois() {
      return { registrar: 'Fake Registrar Inc.', registrationDate: '2000-01-01T00:00:00Z' };
    },
    async dns() {
      return { a: ['93.184.216.34'], ns: ['a.iana-servers.net'] };
    },
    async ssl(domain) {
      return { subject: `CN=${domain}`, issuer: 'CN=Fake CA', daysUntilExpiry: 100 };
    },
    async ports() {
      return { openPorts: [80, 443], services: [{ port: 80, protocol: 'TCP', service: 'HTTP' }] };
    },
    async subdomains(domain) {
      return { subdomains: [`www.${domain}`], sources: { certificateTransparency: [`www.${domain}`], commonNames: [] }, totalFound: 1 };
    },
    ...overrides,
  };
  return fake;
}

async function connectClient(deps: ServerDeps = {}): Promise<Client> {
  const server = createServer({ assertTarget: async () => {}, ...deps });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'test-client', version: '1.0.0' });
  await client.connect(clientTransport);
  return client;
}

function parse(result: any) {
  return JSON.parse(result.content[0].text);
}

describe('MCP server (in-memory transport)', () => {
  it('advertises all six tools with input schemas', async () => {
    const client = await connectClient({ collector: makeCollector() });
    const { tools } = await client.listTools();

    const names = tools.map(t => t.name).sort();
    expect(names).toEqual(['dns_records', 'find_subdomains', 'inspect_domain', 'scan_ports', 'ssl_certificate', 'whois_lookup']);

    // Every tool must declare a `domain` input parameter.
    for (const tool of tools) {
      expect(tool.inputSchema.properties).toHaveProperty('domain');
    }
    const inspect = tools.find(t => t.name === 'inspect_domain')!;
    expect(inspect.inputSchema.properties).toHaveProperty('includePorts');
    expect(inspect.inputSchema.properties).toHaveProperty('includeSubdomains');
    await client.close();
  });

  it('inspect_domain returns the structured analysis payload', async () => {
    const client = await connectClient({ collector: makeCollector() });
    const result = await client.callTool({ name: 'inspect_domain', arguments: { domain: 'example.com' } });
    const payload = parse(result);

    expect(result.isError).toBeFalsy();
    expect(payload.domain).toBe('example.com');
    expect(payload.whois.status).toBe('success');
    expect(payload.whois.data.registrar).toBe('Fake Registrar Inc.');
    expect(payload.dns.status).toBe('success');
    expect(payload.ssl.status).toBe('success');
    expect(payload).toHaveProperty('threatAssessment');
    expect(payload).toHaveProperty('network'); // ports included by default
    await client.close();
  });

  it('caches inspect_domain results (collector invoked once for repeat calls)', async () => {
    const collector = makeCollector();
    const client = await connectClient({ collector });

    await client.callTool({ name: 'inspect_domain', arguments: { domain: 'example.com', includePorts: false } });
    await client.callTool({ name: 'inspect_domain', arguments: { domain: 'example.com', includePorts: false } });
    expect(collector.collectCalls).toBe(1);

    // A different argument set is a different cache key -> a fresh collect.
    await client.callTool({ name: 'inspect_domain', arguments: { domain: 'example.com', includePorts: true } });
    expect(collector.collectCalls).toBe(2);
    await client.close();
  });

  it('includePorts=false maps to a quick collect (no port scan)', async () => {
    let quickSeen: boolean | undefined;
    const collector = makeCollector({
      async collect(_domain, opts) {
        quickSeen = opts?.quick;
        return { domain: _domain, dns: { a: ['1.2.3.4'] } };
      },
    });
    const client = await connectClient({ collector });
    await client.callTool({ name: 'inspect_domain', arguments: { domain: 'example.com', includePorts: false } });
    expect(quickSeen).toBe(true);
    await client.close();
  });

  it('granular tools return their aspect', async () => {
    const client = await connectClient({ collector: makeCollector() });

    const dns = parse(await client.callTool({ name: 'dns_records', arguments: { domain: 'example.com' } }));
    expect(dns.a).toEqual(['93.184.216.34']);

    const whois = parse(await client.callTool({ name: 'whois_lookup', arguments: { domain: 'example.com' } }));
    expect(whois.registrar).toBe('Fake Registrar Inc.');
    await client.close();
  });

  it('a granular tool reports {found:false} when there is no data', async () => {
    const collector = makeCollector({ async ssl() { return null; } });
    const client = await connectClient({ collector });
    const result = await client.callTool({ name: 'ssl_certificate', arguments: { domain: 'example.com' } });
    expect(parse(result)).toEqual({ domain: 'example.com', found: false });
    await client.close();
  });

  it('blocks a guarded target with an isError result (SSRF guard)', async () => {
    const assertTarget = async (domain: string) => {
      if (domain === 'blocked.test') throw new Error('Refusing to inspect internal host: blocked.test');
    };
    const client = await connectClient({ collector: makeCollector(), assertTarget });

    const blocked = await client.callTool({ name: 'scan_ports', arguments: { domain: 'blocked.test' } });
    expect(blocked.isError).toBe(true);
    expect((blocked.content as any)[0].text).toMatch(/internal host/);

    const allowed = await client.callTool({ name: 'scan_ports', arguments: { domain: 'allowed.test' } });
    expect(allowed.isError).toBeFalsy();
    await client.close();
  });

  // The SDK signals a bad call either by rejecting or by returning isError; accept both.
  const failed = (r: unknown) => (r as any)?.isError === true;

  it('fails a call with a missing required argument', async () => {
    const client = await connectClient({ collector: makeCollector() });
    const outcome = await client.callTool({ name: 'inspect_domain', arguments: {} }).then(r => r, () => ({ isError: true }));
    expect(failed(outcome)).toBe(true);
    await client.close();
  });

  it('fails on an unknown tool', async () => {
    const client = await connectClient({ collector: makeCollector() });
    const outcome = await client.callTool({ name: 'nonexistent_tool', arguments: { domain: 'x.com' } }).then(r => r, () => ({ isError: true }));
    expect(failed(outcome)).toBe(true);
    await client.close();
  });
});
