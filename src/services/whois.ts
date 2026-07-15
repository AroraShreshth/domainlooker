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
export function hasKeyRegistrationFields(whois: WhoisData): boolean {
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
    return parseRdapDomain(response.data);
  }

  private legacyLookup(domain: string, timeout: number): Promise<WhoisData> {
    return new Promise((resolve, reject) => {
      whois.lookup(domain, { timeout }, (err: Error | null, data: string) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(parseWhoisText(data));
      });
    });
  }
}

/** Parse an RDAP domain object into our WhoisData shape. Defensive against partial/redacted records. */
export function parseRdapDomain(data: any): WhoisData {
  const result: WhoisData = {};
  if (!data || typeof data !== 'object') return result;

  const entities: any[] = Array.isArray(data.entities) ? data.entities : [];

  const registrar = entities.find(e => Array.isArray(e.roles) && e.roles.includes('registrar'));
  if (registrar) {
    const name = vcardValue(registrar, 'fn');
    if (name) result.registrar = name;
  }

  const registrant = entities.find(e => Array.isArray(e.roles) && e.roles.includes('registrant'));
  if (registrant) {
    const country = vcardCountry(registrant);
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
    const status = data.status.filter((s: any): s is string => typeof s === 'string');
    if (status.length) result.status = status;
  }

  return result;
}

/**
 * Parse raw port-43 WHOIS text. Matches the field label against the KEY (the
 * text before the first colon) rather than the whole line, so disclaimer prose
 * like "NOTICE: The expiration date displayed ..." is not mistaken for a value,
 * and "Registrar WHOIS Server:" is not mistaken for the registrar.
 */
export function parseWhoisText(data: string): WhoisData {
  const result: WhoisData = {};

  for (const line of data.split('\n')) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (!value) continue;

    if (key === 'registrar' || key === 'sponsoring registrar') {
      result.registrar = value;
    } else if (key === 'creation date' || key === 'created' || key === 'created on' || key === 'registered on' || key === 'registration date') {
      result.registrationDate ??= value;
    } else if (/expir/.test(key) && /date/.test(key)) {
      result.expirationDate ??= value;
    } else if (key === 'name server' || key === 'nserver' || key === 'name servers') {
      (result.nameServers ??= []);
      if (!result.nameServers.includes(value)) result.nameServers.push(value);
    } else if (key === 'registrant country') {
      result.registrantCountry = value;
    } else if (key === 'domain status' || key === 'status') {
      (result.status ??= []);
      if (!result.status.includes(value)) result.status.push(value);
    }
  }

  return result;
}

/** Read a value from an RDAP jCard, e.g. `fn` (formatted name). */
function vcardValue(entity: any, key: string): string | undefined {
  const properties = entity?.vcardArray?.[1];
  if (!Array.isArray(properties)) return undefined;
  const property = properties.find((p: any) => Array.isArray(p) && p[0] === key);
  return property && property[3] != null ? String(property[3]) : undefined;
}

/** The country is the last component of a jCard `adr` structured value. */
function vcardCountry(entity: any): string | undefined {
  const properties = entity?.vcardArray?.[1];
  if (!Array.isArray(properties)) return undefined;
  const adr = properties.find((p: any) => Array.isArray(p) && p[0] === 'adr');
  const value = adr?.[3];
  return Array.isArray(value) && value[6] ? String(value[6]) : undefined;
}
