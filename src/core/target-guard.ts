import { promises as dns } from 'dns';
import { isIP } from 'net';

/**
 * Guards against pointing the network probes (port scan, TLS connect, HTTP) at
 * internal infrastructure. The CLI trusts the human running it, but the MCP
 * server is reachable by an AI agent whose "domain" argument may be attacker- or
 * injection-controlled, so MCP tools must run every target through
 * `assertPublicDomain` before touching the network.
 */

const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa'];
const BLOCKED_HOSTS = new Set(['localhost']);

/** Loose "does this look like a hostname" check (a dot, host chars, optional trailing dot). */
export function isDomainShaped(value: string): boolean {
  return /^(?=.{1,254}$)([a-zA-Z0-9_-]+\.)+[a-zA-Z0-9_-]+\.?$/.test(value);
}

export function isPrivateAddress(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return isPrivateV4(ip);
  if (version === 6) return isPrivateV6(ip.toLowerCase());
  return false;
}

function isPrivateV4(ip: string): boolean {
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => Number.isNaN(o) || o < 0 || o > 255)) return true;
  const [a, b] = octets;
  return (
    a === 0 ||                          // 0.0.0.0/8 "this host"
    a === 10 ||                         // private
    a === 127 ||                        // loopback
    (a === 100 && b >= 64 && b <= 127) || // CGNAT 100.64.0.0/10
    (a === 169 && b === 254) ||         // link-local / cloud metadata
    (a === 172 && b >= 16 && b <= 31) ||// private
    (a === 192 && b === 168)            // private
  );
}

function isPrivateV6(ip: string): boolean {
  if (ip === '::1' || ip === '::') return true;
  // IPv4-mapped (::ffff:1.2.3.4) — judge by the embedded IPv4.
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateV4(mapped[1]);
  const head = ip.split(':')[0];
  const prefix = parseInt(head || '0', 16);
  if (Number.isNaN(prefix)) return true;
  if ((prefix & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  if ((prefix & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  return false;
}

/**
 * Reject IP literals, localhost/internal names, non-domain-shaped input, and
 * public names that resolve to private/loopback/link-local addresses.
 * Throws an Error (with a caller-safe message) when the target is not allowed.
 */
export async function assertPublicDomain(domain: string): Promise<void> {
  const host = domain.trim().toLowerCase().replace(/\.$/, '');

  if (isIP(host) !== 0) {
    throw new Error('IP addresses are not accepted; provide a domain name.');
  }
  if (BLOCKED_HOSTS.has(host) || BLOCKED_SUFFIXES.some(s => host.endsWith(s))) {
    throw new Error(`Refusing to inspect internal host: ${domain}`);
  }
  if (!isDomainShaped(host)) {
    throw new Error(`Not a valid domain: ${domain}`);
  }

  const addresses = await dns.lookup(host, { all: true }).catch(() => []);
  for (const { address } of addresses) {
    if (isPrivateAddress(address)) {
      throw new Error(`Refusing to inspect ${domain}: it resolves to a private address (${address}).`);
    }
  }
}
