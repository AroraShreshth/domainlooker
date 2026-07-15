import { spawn, ChildProcessWithoutNullStreams } from 'child_process';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';

const execAsync = promisify(exec);

/**
 * Drives the MCP server over stdio with raw newline-delimited JSON-RPC, so the
 * test does not need to import the ESM MCP SDK inside jest's CJS runtime.
 */
class McpStdioClient {
  private buffer = '';
  private pending = new Map<number, (msg: any) => void>();

  constructor(private child: ChildProcessWithoutNullStreams) {
    child.stdout.on('data', chunk => {
      this.buffer += chunk.toString();
      let idx: number;
      while ((idx = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, idx).trim();
        this.buffer = this.buffer.slice(idx + 1);
        if (!line) continue;
        const msg = JSON.parse(line);
        if (msg.id != null && this.pending.has(msg.id)) {
          this.pending.get(msg.id)!(msg);
          this.pending.delete(msg.id);
        }
      }
    });
  }

  request(id: number, method: string, params: any): Promise<any> {
    return new Promise(resolve => {
      this.pending.set(id, resolve);
      this.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }

  notify(method: string, params: any): void {
    this.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  }
}

describe('MCP server (stdio)', () => {
  const cliPath = path.join(__dirname, '../../dist/index.js');
  let child: ChildProcessWithoutNullStreams;
  let client: McpStdioClient;

  beforeAll(async () => {
    try {
      await execAsync('npm run build');
    } catch (error) {
      console.warn('Build failed, MCP test may not work:', error);
    }
    child = spawn('node', [cliPath, 'mcp'], { stdio: ['pipe', 'pipe', 'pipe'] });
    client = new McpStdioClient(child);

    const init = await client.request(1, 'initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'jest', version: '1.0.0' },
    });
    expect(init.result.serverInfo.name).toBe('domainlooker');
    client.notify('notifications/initialized', {});
  }, 30000);

  afterAll(() => {
    child?.kill();
  });

  it('lists the expected tools', async () => {
    const res = await client.request(2, 'tools/list', {});
    const names = res.result.tools.map((t: any) => t.name).sort();
    expect(names).toEqual(
      ['dns_records', 'find_subdomains', 'inspect_domain', 'scan_ports', 'ssl_certificate', 'whois_lookup'].sort(),
    );
  }, 10000);

  it('inspect_domain returns structured data for a domain', async () => {
    const res = await client.request(3, 'tools/call', {
      name: 'inspect_domain',
      arguments: { domain: 'example.com', includePorts: false },
    });
    const payload = JSON.parse(res.result.content[0].text);
    expect(payload.domain).toBe('example.com');
    expect(payload).toHaveProperty('dns');
    expect(payload).toHaveProperty('ssl');
    expect(payload).toHaveProperty('threatAssessment');
  }, 30000);
});
