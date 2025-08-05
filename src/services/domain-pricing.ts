import axios from 'axios';
import { DomainInfo } from '../types/index.js';

export interface DomainPricing {
  provider: string;
  available: boolean;
  registrationPrice?: number;
  renewalPrice?: number;
  currency: string;
  url: string;
  error?: string;
}

export interface DomainAvailabilityResult {
  domain: string;
  isAvailable: boolean;
  pricing: DomainPricing[];
  checkedAt: Date;
}

export class DomainPricingService {
  private timeout = 10000; // 10 second timeout
  
  async checkAvailabilityAndPricing(domain: string): Promise<DomainAvailabilityResult> {
    console.log(`🔍 Checking domain availability and pricing for ${domain}...`);
    
    const result: DomainAvailabilityResult = {
      domain,
      isAvailable: false,
      pricing: [],
      checkedAt: new Date()
    };

    // Check if domain appears to be unregistered based on WHOIS
    const isLikelyAvailable = await this.quickAvailabilityCheck(domain);
    result.isAvailable = isLikelyAvailable;
    
    if (isLikelyAvailable) {
      // Only check pricing if domain appears available
      const pricingPromises = [
        this.checkCloudflare(domain),
        this.checkNamecheap(domain),
        this.checkPorkbun(domain),
        this.checkGoDaddy(domain),
        this.checkNamecom(domain)
      ];

      const pricingResults = await Promise.allSettled(pricingPromises);
      
      result.pricing = pricingResults
        .map((result, index) => {
          if (result.status === 'fulfilled') {
            return result.value;
          } else {
            const providers = ['Cloudflare', 'Namecheap', 'Porkbun', 'GoDaddy', 'Name.com'];
            return {
              provider: providers[index],
              available: false,
              currency: 'USD',
              url: '',
              error: result.reason?.message || 'Failed to check pricing'
            };
          }
        })
        .filter(pricing => pricing !== null) as DomainPricing[];
    }

    return result;
  }

  private async quickAvailabilityCheck(domain: string): Promise<boolean> {
    try {
      // Simple DNS lookup to check if domain has any records
      const response = await axios.get(`https://dns.google/resolve?name=${domain}&type=A`, {
        timeout: this.timeout,
        headers: {
          'User-Agent': 'DOMAINLOOKER/1.0'
        }
      });

      // If DNS lookup fails or returns NXDOMAIN-like response, domain might be available
      return response.data?.Status === 3 || // NXDOMAIN
             !response.data?.Answer || 
             response.data?.Answer.length === 0;
    } catch (error) {
      // If DNS lookup fails, assume domain might be available
      return true;
    }
  }

  private async checkCloudflare(domain: string): Promise<DomainPricing> {
    try {
      // Cloudflare doesn't have a public API for domain pricing
      // We'll provide estimated pricing based on known rates
      const tld = domain.split('.').pop()?.toLowerCase();
      const pricing = this.getCloudflareEstimatedPricing(tld);
      
      return {
        provider: 'Cloudflare',
        available: true, // Assume available if we're checking
        registrationPrice: pricing.registration ?? undefined,
        renewalPrice: pricing.renewal ?? undefined,
        currency: 'USD',
        url: `https://www.cloudflare.com/products/registrar/`,
        error: pricing.registration === null ? 'TLD not supported' : undefined
      };
    } catch (error) {
      return {
        provider: 'Cloudflare',
        available: false,
        currency: 'USD',
        url: 'https://www.cloudflare.com/products/registrar/',
        error: 'Failed to check Cloudflare pricing'
      };
    }
  }

  private async checkNamecheap(domain: string): Promise<DomainPricing> {
    try {
      // Namecheap doesn't have a public pricing API
      // We'll provide estimated pricing based on known rates
      const tld = domain.split('.').pop()?.toLowerCase();
      const pricing = this.getNamecheapEstimatedPricing(tld);
      
      return {
        provider: 'Namecheap',
        available: true,
        registrationPrice: pricing.registration ?? undefined,
        renewalPrice: pricing.renewal ?? undefined,
        currency: 'USD',
        url: `https://www.namecheap.com/domains/registration/results/?domain=${domain}`,
        error: pricing.registration === null ? 'TLD not supported' : undefined
      };
    } catch (error) {
      return {
        provider: 'Namecheap',
        available: false,
        currency: 'USD',
        url: `https://www.namecheap.com/domains/registration/results/?domain=${domain}`,
        error: 'Failed to check Namecheap pricing'
      };
    }
  }

  private async checkPorkbun(domain: string): Promise<DomainPricing> {
    try {
      // Porkbun has a public API but requires authentication for domain checks
      // We'll provide estimated pricing based on known rates
      const tld = domain.split('.').pop()?.toLowerCase();
      const pricing = this.getPorkbunEstimatedPricing(tld);
      
      return {
        provider: 'Porkbun',
        available: true,
        registrationPrice: pricing.registration ?? undefined,
        renewalPrice: pricing.renewal ?? undefined,
        currency: 'USD',
        url: `https://porkbun.com/checkout/search?q=${domain}`,
        error: pricing.registration === null ? 'TLD not supported' : undefined
      };
    } catch (error) {
      return {
        provider: 'Porkbun',
        available: false,
        currency: 'USD',
        url: `https://porkbun.com/checkout/search?q=${domain}`,
        error: 'Failed to check Porkbun pricing'
      };
    }
  }

  private async checkGoDaddy(domain: string): Promise<DomainPricing> {
    try {
      // GoDaddy has APIs but they're complex and require authentication
      // We'll provide estimated pricing based on known rates
      const tld = domain.split('.').pop()?.toLowerCase();
      const pricing = this.getGoDaddyEstimatedPricing(tld);
      
      return {
        provider: 'GoDaddy',
        available: true,
        registrationPrice: pricing.registration ?? undefined,
        renewalPrice: pricing.renewal ?? undefined,
        currency: 'USD',
        url: `https://www.godaddy.com/domainsearch/find?checkAvail=1&domainToCheck=${domain}`,
        error: pricing.registration === null ? 'TLD not supported' : undefined
      };
    } catch (error) {
      return {
        provider: 'GoDaddy',
        available: false,
        currency: 'USD',
        url: `https://www.godaddy.com/domainsearch/find?checkAvail=1&domainToCheck=${domain}`,
        error: 'Failed to check GoDaddy pricing'
      };
    }
  }

  private async checkNamecom(domain: string): Promise<DomainPricing> {
    try {
      const tld = domain.split('.').pop()?.toLowerCase();
      const pricing = this.getNamecomEstimatedPricing(tld);
      
      return {
        provider: 'Name.com',
        available: true,
        registrationPrice: pricing.registration ?? undefined,
        renewalPrice: pricing.renewal ?? undefined,
        currency: 'USD',
        url: `https://www.name.com/domain/search/${domain}`,
        error: pricing.registration === null ? 'TLD not supported' : undefined
      };
    } catch (error) {
      return {
        provider: 'Name.com',
        available: false,
        currency: 'USD',
        url: `https://www.name.com/domain/search/${domain}`,
        error: 'Failed to check Name.com pricing'
      };
    }
  }

  // Estimated pricing based on current market rates (as of 2025)
  private getCloudflareEstimatedPricing(tld?: string): { registration: number | null; renewal: number | null } {
    const pricing: Record<string, { registration: number; renewal: number }> = {
      'com': { registration: 9.77, renewal: 9.77 },
      'net': { registration: 11.85, renewal: 11.85 },
      'org': { registration: 12.06, renewal: 12.06 },
      'info': { registration: 4.85, renewal: 17.85 },
      'biz': { registration: 4.85, renewal: 17.85 },
      'us': { registration: 8.57, renewal: 8.57 },
      'co': { registration: 30.00, renewal: 30.00 },
      'io': { registration: 65.00, renewal: 65.00 },
      'dev': { registration: 15.00, renewal: 15.00 },
      'app': { registration: 20.00, renewal: 20.00 }
    };
    
    return pricing[tld || ''] || { registration: null, renewal: null };
  }

  private getNamecheapEstimatedPricing(tld?: string): { registration: number | null; renewal: number | null } {
    const pricing: Record<string, { registration: number; renewal: number }> = {
      'com': { registration: 10.99, renewal: 13.99 },
      'net': { registration: 12.99, renewal: 15.99 },
      'org': { registration: 11.99, renewal: 14.99 },
      'info': { registration: 2.99, renewal: 21.99 },
      'biz': { registration: 1.99, renewal: 19.99 },
      'us': { registration: 8.88, renewal: 8.88 },
      'co': { registration: 8.88, renewal: 32.99 },
      'io': { registration: 39.99, renewal: 69.99 },
      'dev': { registration: 12.99, renewal: 17.99 },
      'app': { registration: 14.99, renewal: 20.99 }
    };
    
    return pricing[tld || ''] || { registration: null, renewal: null };
  }

  private getPorkbunEstimatedPricing(tld?: string): { registration: number | null; renewal: number | null } {
    const pricing: Record<string, { registration: number; renewal: number }> = {
      'com': { registration: 8.97, renewal: 9.73 },
      'net': { registration: 10.69, renewal: 11.84 },
      'org': { registration: 9.17, renewal: 12.18 },
      'info': { registration: 3.25, renewal: 17.67 },
      'biz': { registration: 4.14, renewal: 18.44 },
      'us': { registration: 7.65, renewal: 8.37 },
      'co': { registration: 6.98, renewal: 30.78 },
      'io': { registration: 47.20, renewal: 54.00 },
      'dev': { registration: 11.48, renewal: 15.33 },
      'app': { registration: 15.33, renewal: 18.44 }
    };
    
    return pricing[tld || ''] || { registration: null, renewal: null };
  }

  private getGoDaddyEstimatedPricing(tld?: string): { registration: number | null; renewal: number | null } {
    const pricing: Record<string, { registration: number; renewal: number }> = {
      'com': { registration: 11.99, renewal: 17.99 },
      'net': { registration: 12.99, renewal: 17.99 },
      'org': { registration: 12.99, renewal: 17.99 },
      'info': { registration: 2.99, renewal: 19.99 },
      'biz': { registration: 2.99, renewal: 19.99 },
      'us': { registration: 9.99, renewal: 9.99 },
      'co': { registration: 24.99, renewal: 34.99 },
      'io': { registration: 59.99, renewal: 79.99 },
      'dev': { registration: 17.99, renewal: 24.99 },
      'app': { registration: 19.99, renewal: 24.99 }
    };
    
    return pricing[tld || ''] || { registration: null, renewal: null };
  }

  private getNamecomEstimatedPricing(tld?: string): { registration: number | null; renewal: number | null } {
    const pricing: Record<string, { registration: number; renewal: number }> = {
      'com': { registration: 10.99, renewal: 12.99 },
      'net': { registration: 12.99, renewal: 14.99 },
      'org': { registration: 11.99, renewal: 13.99 },
      'info': { registration: 4.99, renewal: 18.99 },
      'biz': { registration: 4.99, renewal: 18.99 },
      'us': { registration: 8.99, renewal: 8.99 },
      'co': { registration: 29.99, renewal: 31.99 },
      'io': { registration: 49.99, renewal: 69.99 },
      'dev': { registration: 14.99, renewal: 19.99 },
      'app': { registration: 17.99, renewal: 22.99 }
    };
    
    return pricing[tld || ''] || { registration: null, renewal: null };
  }
}