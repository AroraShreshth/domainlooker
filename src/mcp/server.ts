import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { DomainCollector, CollectOptions } from '../core/collector.js';
import { JsonExportService } from '../services/json-export.js';
import { DomainInfo } from '../types/index.js';
import { DomainAnalysisData } from '../types/api-schema.js';

const VERSION = '0.2.0';
const CACHE_TTL_MS = 5 * 60 * 1000; // domain data changes slowly; 5 minutes keeps repeat calls instant
const CACHE_MAX_ENTRIES = 500;

interface CacheEntry {
  expires: number;
  value: DomainAnalysisData;
}

/** Transform a raw DomainInfo into the structured export schema (same shape as --export-json). */
function toAnalysis(info: DomainInfo, options: CollectOptions): DomainAnalysisData {
  const exporter = new JsonExportService({ quick: options.quick, subdomains: options.subdomains });
  exporter.addDomain(info);
  return exporter.getStructuredData().data[0];
}

function textResult(value: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }] };
}

/** Render a granular lookup result, making "no data" explicit rather than a bare null. */
function lookupResult(domain: string, value: unknown) {
  return textResult(value ?? { domain, found: false });
}

export function createServer(): McpServer {
  const collector = new DomainCollector();
  const cache = new Map<string, CacheEntry>();

  const cacheWrite = (key: string, value: DomainAnalysisData): void => {
    const now = Date.now();
    // Drop expired entries, then bound total size (oldest-first) so a long-lived
    // server queried across many domains cannot grow the cache without limit.
    for (const [k, entry] of cache) {
      if (entry.expires <= now) cache.delete(k);
    }
    while (cache.size >= CACHE_MAX_ENTRIES) {
      const oldest = cache.keys().next().value;
      if (oldest === undefined) break;
      cache.delete(oldest);
    }
    cache.set(key, { expires: now + CACHE_TTL_MS, value });
  };

  const server = new McpServer({ name: 'domainlooker', version: VERSION });

  const domainArg = z.string().min(1).describe('The domain to inspect, e.g. "example.com"');

  // Primary tool: everything about a domain in one structured payload.
  server.registerTool(
    'inspect_domain',
    {
      title: 'Inspect domain',
      description:
        'Fetch full intelligence for a domain (WHOIS/RDAP registration, DNS records, ' +
        'SSL certificate, open ports, and rule-based advisories) as one structured JSON object. ' +
        'Results are cached for a few minutes, so repeated calls are instant.',
      inputSchema: {
        domain: domainArg,
        includePorts: z.boolean().optional().describe('Scan common ports (default true).'),
        includeSubdomains: z.boolean().optional().describe('Discover subdomains — slower (default false).'),
      },
    },
    async ({ domain, includePorts, includeSubdomains }) => {
      const options: CollectOptions = {
        quick: includePorts === false,
        subdomains: includeSubdomains === true,
      };
      const key = `${domain}|ports=${options.quick ? 0 : 1}|subs=${options.subdomains ? 1 : 0}`;

      const cached = cache.get(key);
      if (cached && cached.expires > Date.now()) {
        return textResult(cached.value);
      }

      const info = await collector.collect(domain, options);
      const analysis = toAnalysis(info, options);
      cacheWrite(key, analysis);
      return textResult(analysis);
    },
  );

  // Granular tools mirror the CLI subcommands, for agents that need just one aspect fast.
  server.registerTool(
    'whois_lookup',
    { title: 'WHOIS lookup', description: 'Registration data (registrar, dates, name servers, status) via RDAP with WHOIS fallback.', inputSchema: { domain: domainArg } },
    async ({ domain }) => lookupResult(domain, await collector.whois(domain)),
  );

  server.registerTool(
    'dns_records',
    { title: 'DNS records', description: 'A, AAAA, MX, NS, TXT, and SOA records for a domain.', inputSchema: { domain: domainArg } },
    async ({ domain }) => lookupResult(domain, await collector.dns(domain)),
  );

  server.registerTool(
    'ssl_certificate',
    { title: 'SSL certificate', description: 'TLS certificate details and days until expiry.', inputSchema: { domain: domainArg } },
    async ({ domain }) => lookupResult(domain, await collector.ssl(domain)),
  );

  server.registerTool(
    'scan_ports',
    { title: 'Scan ports', description: 'Scan common TCP ports and identify the services behind the open ones.', inputSchema: { domain: domainArg } },
    async ({ domain }) => lookupResult(domain, await collector.ports(domain)),
  );

  server.registerTool(
    'find_subdomains',
    { title: 'Find subdomains', description: 'Discover subdomains via certificate transparency and common-name checks.', inputSchema: { domain: domainArg } },
    async ({ domain }) => lookupResult(domain, await collector.subdomains(domain)),
  );

  return server;
}

/** Start the MCP server over stdio. Only MCP protocol messages go to stdout. */
export async function startStdioServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
