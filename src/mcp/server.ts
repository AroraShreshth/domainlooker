import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { DomainCollector, CollectOptions } from '../core/collector.js';
import { assertPublicDomain } from '../core/target-guard.js';
import { JsonExportService } from '../services/json-export.js';
import { DomainInfo } from '../types/index.js';
import { DomainAnalysisData } from '../types/api-schema.js';
import { VERSION } from '../version.js';

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

/** An MCP error result carrying a caller-safe message (e.g. a blocked target). */
function guardError(error: unknown) {
  return {
    content: [{ type: 'text' as const, text: error instanceof Error ? error.message : String(error) }],
    isError: true,
  };
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
      try {
        await assertPublicDomain(domain);
      } catch (error) {
        return guardError(error);
      }

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
  // Every tool runs the target through `assertPublicDomain` first, so an agent
  // cannot turn the server into a scanner of internal/loopback/metadata hosts.
  const granularTool = (
    name: string,
    title: string,
    description: string,
    run: (domain: string) => Promise<unknown>,
  ) => {
    server.registerTool(name, { title, description, inputSchema: { domain: domainArg } }, async ({ domain }) => {
      try {
        await assertPublicDomain(domain);
      } catch (error) {
        return guardError(error);
      }
      return lookupResult(domain, await run(domain));
    });
  };

  granularTool('whois_lookup', 'WHOIS lookup', 'Registration data (registrar, dates, name servers, status) via RDAP with WHOIS fallback.', d => collector.whois(d));
  granularTool('dns_records', 'DNS records', 'A, AAAA, MX, NS, TXT, and SOA records for a domain.', d => collector.dns(d));
  granularTool('ssl_certificate', 'SSL certificate', 'TLS certificate details and days until expiry.', d => collector.ssl(d));
  granularTool('scan_ports', 'Scan ports', 'Scan common TCP ports and identify the services behind the open ones.', d => collector.ports(d));
  granularTool('find_subdomains', 'Find subdomains', 'Discover subdomains via certificate transparency and common-name checks.', d => collector.subdomains(d));

  return server;
}

/** Start the MCP server over stdio. Only MCP protocol messages go to stdout. */
export async function startStdioServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
