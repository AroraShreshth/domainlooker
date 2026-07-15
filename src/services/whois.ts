import whois from 'whois';
import axios from 'axios';
import { WhoisData } from '../types/index.js';

const RDAP_TIMEOUT_MS = 3500;
const WHOIS_TIMEOUT_MS = 6000;

export interface WhoisLookupOptions {
  /** Socket timeout (ms) for the legacy port-43 fallback. */
  timeout?: number;
  /** HTTP timeout (ms) for the RDAP request. */
  rdapTimeout?: number;
}

/** RDAP that lacks these carries too little to prefer over a port-43 record. */
function hasKeyRegistrationFields(whois: WhoisData): boolean {
  return !!(whois.registrar || whois.registrationDate || whois.expirationDate);
}

/**
 * Registration lookups. RDAP (HTTP/JSON) is tried first because it is fast and
 * already structured; the legacy port-43 WHOIS protocol is used as a fallback
 * for registries whose RDAP is missing, sparse, or redacted.
 */
export class WhoisService {
  async lookup(domain: string, options: WhoisLookupOptions = {}): Promise<WhoisData> {
    const rdap = await this.rdapLookup(domain, options.rdapTimeout ?? RDAP_TIMEOUT_MS).catch(() => null);

    // Only short-circuit on RDAP when it actually carries the registration
    // details; a sparse/redacted RDAP record shouldn't hide a richer WHOIS one.
    if (rdap && hasKeyRegistrationFields(rdap)) {
      return rdap;
    }

    try {
      const legacy = await this.legacyLookup(domain, options.timeout ?? WHOIS_TIMEOUT_MS);
      if (Object.keys(legacy).length > 0) {
        return legacy;
      }
    } catch {
      // Legacy WHOIS failed; fall through to whatever partial RDAP we have.
    }

    // Better a partial RDAP record (e.g. just nameservers/status) than nothing.
    return rdap ?? {};
  }

  private async rdapLookup(domain: string, timeoutMs: number): Promise<WhoisData | null> {
    // rdap.org bootstraps to the authoritative RDAP server via redirect.
    const response = await axios.get(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      timeout: timeoutMs,
      headers: { Accept: 'application/rdap+json', 'User-Agent': 'domainlooker' },
    });
    return this.parseRdap(response.data);
  }

  private parseRdap(data: any): WhoisData {
    const result: WhoisData = {};
    if (!data || typeof data !== 'object') return result;

    const entities: any[] = Array.isArray(data.entities) ? data.entities : [];

    const registrar = entities.find(e => Array.isArray(e.roles) && e.roles.includes('registrar'));
    if (registrar) {
      const name = this.vcardValue(registrar, 'fn');
      if (name) result.registrar = name;
    }

    const registrant = entities.find(e => Array.isArray(e.roles) && e.roles.includes('registrant'));
    if (registrant) {
      const country = this.vcardCountry(registrant);
      if (country) result.registrantCountry = country;
    }

    const events: any[] = Array.isArray(data.events) ? data.events : [];
    const registration = events.find(e => e.eventAction === 'registration');
    const expiration = events.find(e => e.eventAction === 'expiration');
    if (registration?.eventDate) result.registrationDate = registration.eventDate;
    if (expiration?.eventDate) result.expirationDate = expiration.eventDate;

    const nameServers = (Array.isArray(data.nameservers) ? data.nameservers : [])
      .map((ns: any) => ns?.ldhName)
      .filter((n: any): n is string => typeof n === 'string');
    if (nameServers.length) result.nameServers = nameServers;

    if (Array.isArray(data.status) && data.status.length) {
      result.status = data.status.filter((s: any): s is string => typeof s === 'string');
    }

    return result;
  }

  /** Read a value from an RDAP jCard, e.g. `fn` (formatted name). */
  private vcardValue(entity: any, key: string): string | undefined {
    const properties = entity?.vcardArray?.[1];
    if (!Array.isArray(properties)) return undefined;
    const property = properties.find((p: any) => Array.isArray(p) && p[0] === key);
    return property && property[3] != null ? String(property[3]) : undefined;
  }

  /** The country is the last component of a jCard `adr` structured value. */
  private vcardCountry(entity: any): string | undefined {
    const properties = entity?.vcardArray?.[1];
    if (!Array.isArray(properties)) return undefined;
    const adr = properties.find((p: any) => Array.isArray(p) && p[0] === 'adr');
    const value = adr?.[3];
    return Array.isArray(value) && value[6] ? String(value[6]) : undefined;
  }

  private legacyLookup(domain: string, timeout: number): Promise<WhoisData> {
    return new Promise((resolve, reject) => {
      whois.lookup(domain, { timeout }, (err: Error | null, data: string) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(this.parseWhoisData(data));
      });
    });
  }

  private parseWhoisData(data: string): WhoisData {
    const lines = data.split('\n');
    const result: WhoisData = {};

    for (const line of lines) {
      const trimmed = line.trim();

      if (trimmed.match(/registrar:/i)) {
        result.registrar = this.extractValue(trimmed);
      } else if (trimmed.match(/creation date|registered on|registration date:/i)) {
        result.registrationDate = this.extractValue(trimmed);
      } else if (trimmed.match(/expir|expiry date|expires on:/i)) {
        result.expirationDate = this.extractValue(trimmed);
      } else if (trimmed.match(/name server|nserver:/i)) {
        if (!result.nameServers) result.nameServers = [];
        const ns = this.extractValue(trimmed);
        if (ns && !result.nameServers.includes(ns)) {
          result.nameServers.push(ns);
        }
      } else if (trimmed.match(/registrant country:/i)) {
        result.registrantCountry = this.extractValue(trimmed);
      } else if (trimmed.match(/status:/i)) {
        if (!result.status) result.status = [];
        const status = this.extractValue(trimmed);
        if (status && !result.status.includes(status)) {
          result.status.push(status);
        }
      }
    }

    return result;
  }

  private extractValue(line: string): string | undefined {
    const parts = line.split(':');
    if (parts.length > 1) {
      return parts.slice(1).join(':').trim();
    }
    return undefined;
  }
}
