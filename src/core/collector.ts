import { WhoisService } from '../services/whois.js';
import { DNSService } from '../services/dns.js';
import { SSLService } from '../services/ssl.js';
import { NetworkService } from '../services/network.js';
import { SubdomainService } from '../services/subdomain.js';
import {
  DomainInfo,
  WhoisData,
  DNSData,
  SSLData,
  NetworkData,
  SubdomainData,
} from '../types/index.js';

export interface CollectOptions {
  /** Skip the port scan (the slowest part of a full report). */
  quick?: boolean;
  /** Include subdomain discovery (certificate transparency + common names). */
  subdomains?: boolean;
  /** Per-service timeout overrides (ms). */
  whoisTimeoutMs?: number;
  rdapTimeoutMs?: number;
  sslTimeoutMs?: number;
  portTimeoutMs?: number;
  /** Called with each service failure; lets callers surface errors without the collector printing anything. */
  onError?: (service: string, error: unknown) => void;
}

export function hasWhoisData(whois: WhoisData | null | undefined): whois is WhoisData {
  // A parser can leave a key set to `undefined` (a matched label with no value),
  // so require at least one field with an actual value — not merely a key.
  return !!whois && Object.values(whois).some(v => v != null && (!Array.isArray(v) || v.length > 0));
}

export function hasDnsData(dns: DNSData | null | undefined): dns is DNSData {
  return !!dns && Object.values(dns).some(v => v != null && (!Array.isArray(v) || v.length > 0));
}

/** Lightweight, factual checks surfaced at the end of a report and in exports. */
export function collectAdvisories(info: DomainInfo): string[] {
  const advisories: string[] = [];

  if (!info.ssl) {
    advisories.push('No SSL certificate detected.');
  } else if (info.ssl.daysUntilExpiry !== undefined && info.ssl.daysUntilExpiry < 30) {
    advisories.push(`SSL certificate expires in ${info.ssl.daysUntilExpiry} days.`);
  }

  if (info.whois?.registrationDate) {
    const days = (Date.now() - new Date(info.whois.registrationDate).getTime()) / 86_400_000;
    if (days >= 0 && days < 30) {
      advisories.push(`Domain was registered ${Math.round(days)} days ago.`);
    }
  }

  return advisories;
}

/**
 * Gathers domain intelligence with no side effects (no console output, no
 * spinners). Every method resolves to its data or `null` and never rejects, so
 * callers can run them concurrently and compose the results freely. This is the
 * shared engine behind both the CLI and the MCP server.
 */
export class DomainCollector {
  private whoisService = new WhoisService();
  private dnsService = new DNSService();
  private sslService = new SSLService();
  private networkService = new NetworkService();
  private subdomainService = new SubdomainService();

  /** Run every enabled lookup in parallel; total time is bounded by the slowest one. */
  async collect(domain: string, options: CollectOptions = {}): Promise<DomainInfo> {
    const info: DomainInfo = { domain };

    const tasks: Array<Promise<void>> = [
      this.whois(domain, options).then(r => { info.whois = r ?? undefined; }),
      this.dns(domain, options).then(r => { info.dns = r ?? undefined; }),
      this.ssl(domain, options).then(r => { info.ssl = r ?? undefined; }),
    ];
    if (!options.quick) {
      tasks.push(this.ports(domain, options).then(r => { info.network = r ?? undefined; }));
    }
    if (options.subdomains) {
      tasks.push(this.subdomains(domain, options).then(r => { info.subdomains = r ?? undefined; }));
    }

    await Promise.all(tasks);
    return info;
  }

  async whois(domain: string, options: CollectOptions = {}): Promise<WhoisData | null> {
    try {
      const result = await this.whoisService.lookup(domain, {
        timeout: options.whoisTimeoutMs,
        rdapTimeout: options.rdapTimeoutMs,
      });
      // A lookup can succeed while yielding nothing usable; report that as "no data".
      return hasWhoisData(result) ? result : null;
    } catch (error) {
      options.onError?.('whois', error);
      return null;
    }
  }

  async dns(domain: string, options: CollectOptions = {}): Promise<DNSData | null> {
    try {
      return await this.dnsService.lookup(domain);
    } catch (error) {
      options.onError?.('dns', error);
      return null;
    }
  }

  async ssl(domain: string, options: CollectOptions = {}): Promise<SSLData | null> {
    try {
      return await this.sslService.getCertificate(domain, 443, options.sslTimeoutMs);
    } catch (error) {
      options.onError?.('ssl', error);
      return null;
    }
  }

  async ports(domain: string, options: CollectOptions = {}): Promise<NetworkData | null> {
    try {
      return await this.networkService.getNetworkInfo(domain, { timeoutMs: options.portTimeoutMs });
    } catch (error) {
      options.onError?.('ports', error);
      return null;
    }
  }

  async subdomains(domain: string, options: CollectOptions = {}): Promise<SubdomainData | null> {
    try {
      return await this.subdomainService.discoverSubdomains(domain);
    } catch (error) {
      options.onError?.('subdomains', error);
      return null;
    }
  }
}
