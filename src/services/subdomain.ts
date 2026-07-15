import { promises as dns } from 'dns';
import axios from 'axios';
import { SubdomainData } from '../types/index.js';

export class SubdomainService {
  private commonSubdomains = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
    'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'm', 'dev', 'staging', 'test',
    'api', 'admin', 'blog', 'shop', 'cdn', 'assets', 'static', 'img', 'images', 'media',
    'secure', 'vpn', 'remote', 'support', 'help', 'docs', 'status', 'monitor', 'demo',
    'beta', 'alpha', 'preview', 'sandbox', 'app', 'portal', 'dashboard', 'panel', 'control',
    'git', 'repo', 'code', 'build', 'ci', 'jenkins', 'gitlab', 'github', 'bitbucket',
    'email', 'imap', 'pop3', 'exchange', 'outlook', 'office', 'calendar', 'contacts',
    'intranet', 'extranet', 'internal', 'external', 'public', 'private', 'secure2',
    'news', 'press', 'media2', 'content', 'cms', 'editor', 'author', 'writer',
    'video', 'stream', 'live', 'broadcast', 'radio', 'podcast', 'audio', 'music',
    'files', 'download', 'upload', 'share', 'cloud', 'storage', 'backup', 'archive',
    'search', 'find', 'directory', 'index', 'catalog', 'library', 'database', 'db',
    'forum', 'community', 'social', 'chat', 'discuss', 'feedback', 'comments', 'reviews'
  ];

  async discoverSubdomains(domain: string): Promise<SubdomainData> {
    const sources = {
      certificateTransparency: [] as string[],
      commonNames: [] as string[]
    };

    // Wildcard DNS makes the common-name resolution check meaningless (every name
    // resolves), so skip it when a wildcard is present and rely on cert transparency.
    const hasWildcard = await this.checkWildcardDNS(domain);

    const [ctResults, commonResults] = await Promise.allSettled([
      this.certificateTransparencyLookup(domain),
      hasWildcard ? Promise.resolve([]) : this.commonSubdomainCheck(domain)
    ]);

    if (ctResults.status === 'fulfilled') {
      sources.certificateTransparency = ctResults.value;
    }

    if (commonResults.status === 'fulfilled') {
      sources.commonNames = commonResults.value;
    }

    // Combine and deduplicate all found subdomains
    const allSubdomains = new Set([
      ...sources.certificateTransparency,
      ...sources.commonNames
    ]);

    const subdomains = Array.from(allSubdomains).sort();

    return {
      subdomains,
      sources,
      totalFound: subdomains.length
    };
  }

  private async certificateTransparencyLookup(domain: string): Promise<string[]> {
    const subdomains: string[] = [];

    try {
      // Use crt.sh API for certificate transparency logs
      const response = await axios.get(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, {
        timeout: 10000,
        headers: {
          'User-Agent': 'DOMAINLOOKER/1.0 Security Research Tool'
        }
      });

      if (response.data && Array.isArray(response.data)) {
        const certificates = response.data;
        const subdomainSet = new Set<string>();

        certificates.forEach((cert: any) => {
          if (cert.name_value) {
            const names = cert.name_value.split('\n');
            names.forEach((name: string) => {
              name = name.trim().toLowerCase();
              
              // Filter valid subdomains
              if (name.endsWith(`.${domain}`) && name !== domain) {
                // Remove wildcards and get the subdomain
                const cleanName = name.replace(/^\*\./, '');
                if (cleanName !== domain && this.isValidSubdomain(cleanName, domain)) {
                  subdomainSet.add(cleanName);
                }
              }
            });
          }
        });

        subdomains.push(...Array.from(subdomainSet));
      }
    } catch (error) {
      // Certificate transparency lookup failed
    }

    return subdomains;
  }

  private async commonSubdomainCheck(domain: string): Promise<string[]> {
    const foundSubdomains: string[] = [];
    const batchSize = 10; // Process in batches to avoid overwhelming DNS servers

    for (let i = 0; i < this.commonSubdomains.length; i += batchSize) {
      const batch = this.commonSubdomains.slice(i, i + batchSize);
      const batchPromises = batch.map(subdomain => this.checkSubdomain(subdomain, domain));
      
      const results = await Promise.allSettled(batchPromises);
      
      results.forEach((result, index) => {
        if (result.status === 'fulfilled' && result.value) {
          foundSubdomains.push(`${batch[index]}.${domain}`);
        }
      });

      // Small delay between batches to be respectful
      if (i + batchSize < this.commonSubdomains.length) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }

    return foundSubdomains;
  }

  private async checkSubdomain(subdomain: string, domain: string): Promise<boolean> {
    const fullDomain = `${subdomain}.${domain}`;
    
    try {
      // Try both A and AAAA records
      const [aRecords, aaaaRecords] = await Promise.allSettled([
        dns.resolve4(fullDomain),
        dns.resolve6(fullDomain)
      ]);

      return aRecords.status === 'fulfilled' || aaaaRecords.status === 'fulfilled';
    } catch (error) {
      return false;
    }
  }

  private async checkWildcardDNS(domain: string): Promise<boolean> {
    try {
      // Check if a random subdomain resolves (indicating wildcard DNS)
      const randomSubdomain = `random-${Date.now()}-test.${domain}`;
      await dns.resolve4(randomSubdomain);
      return true; // Wildcard DNS detected
    } catch (error) {
      return false; // No wildcard DNS
    }
  }

  private isValidSubdomain(subdomain: string, baseDomain: string): boolean {
    // Basic validation for subdomain format
    if (!subdomain || subdomain === baseDomain) return false;
    
    // Check if it's actually a subdomain of the base domain
    if (!subdomain.endsWith(`.${baseDomain}`)) return false;
    
    // Remove the base domain part
    const subPart = subdomain.replace(`.${baseDomain}`, '');
    
    // Check for valid subdomain characters
    const validSubdomainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
    
    return validSubdomainRegex.test(subPart);
  }
}