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
  private timeout = 15000; // 15 second timeout for API calls
  
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
      // Try Porkbun's availability check first (more accurate for domain registration)
      const porkbunAvailability = await this.checkPorkbunAvailability(domain);
      if (porkbunAvailability !== null) {
        return porkbunAvailability;
      }

      // Fall back to DNS lookup to check if domain has any records
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

  private async checkPorkbunAvailability(domain: string): Promise<boolean | null> {
    try {
      // Porkbun's domain check API (requires API key for full access, but we can try)
      const response = await axios.post(`https://api.porkbun.com/api/json/v3/domain/checkDomain/${domain}`, {}, {
        timeout: this.timeout,
        headers: {
          'User-Agent': 'DOMAINLOOKER/1.0',
          'Content-Type': 'application/json'
        }
      });

      if (response.data?.status === 'SUCCESS' && response.data?.avail !== undefined) {
        return response.data.avail === 'yes';
      }
      
      return null;
    } catch (error) {
      // API key required or rate limited, return null to fall back
      return null;
    }
  }

  private async checkCloudflare(domain: string): Promise<DomainPricing> {
    try {
      // Try to get live Cloudflare pricing - NO FALLBACKS
      const tld = domain.split('.').pop()?.toLowerCase();
      const livePricing = await this.getCloudflareLivePricing(tld);
      
      if (!livePricing || livePricing.registration === null) {
        throw new Error('Live API returned no pricing data');
      }
      
      return {
        provider: 'Cloudflare',
        available: true,
        registrationPrice: livePricing.registration,
        renewalPrice: livePricing.renewal ?? undefined,
        currency: 'USD',
        url: `https://www.cloudflare.com/products/registrar/`,
        error: undefined
      };
    } catch (error) {
      return {
        provider: 'Cloudflare',
        available: false,
        currency: 'USD',
        url: 'https://www.cloudflare.com/products/registrar/',
        error: `Failed to get live pricing: ${error}`
      };
    }
  }

  private async checkNamecheap(domain: string): Promise<DomainPricing> {
    try {
      // Try live Namecheap API first
      const livePricing = await this.getNamecheapLivePricing(domain);
      if (livePricing) {
        return {
          provider: 'Namecheap',
          available: true,
          registrationPrice: livePricing.registration ?? undefined,
          renewalPrice: livePricing.renewal ?? undefined,
          currency: 'USD',
          url: `https://www.namecheap.com/domains/registration/results/?domain=${domain}`,
          error: undefined
        };
      }

      // If live API fails, try web scraping their pricing page
      const scrapedPricing = await this.scrapeNamecheapPricing(domain);
      if (scrapedPricing) {
        return {
          provider: 'Namecheap',
          available: true,
          registrationPrice: scrapedPricing.registration ?? undefined,
          renewalPrice: scrapedPricing.renewal ?? undefined,
          currency: 'USD',
          url: `https://www.namecheap.com/domains/registration/results/?domain=${domain}`,
          error: 'Live pricing via web scraping'
        };
      }

      throw new Error('No live pricing available');
    } catch (error) {
      return {
        provider: 'Namecheap',
        available: false,
        currency: 'USD',
        url: `https://www.namecheap.com/domains/registration/results/?domain=${domain}`,
        error: `Failed to get live pricing: ${error}`
      };
    }
  }

  private async checkPorkbun(domain: string): Promise<DomainPricing> {
    try {
      // Get live pricing data for the TLD - NO FALLBACKS
      const tld = domain.split('.').pop()?.toLowerCase();
      const livePricing = await this.getPorkbunLivePricing(tld);
      
      if (!livePricing || livePricing.registration === null) {
        throw new Error('Live API returned no pricing data');
      }
      
      return {
        provider: 'Porkbun',
        available: true,
        registrationPrice: livePricing.registration,
        renewalPrice: livePricing.renewal ?? undefined,
        currency: 'USD',
        url: `https://porkbun.com/checkout/search?q=${domain}`,
        error: undefined
      };
    } catch (error) {
      return {
        provider: 'Porkbun',
        available: false,
        currency: 'USD',
        url: `https://porkbun.com/checkout/search?q=${domain}`,
        error: `Failed to get live pricing: ${error}`
      };
    }
  }

  private async checkGoDaddy(domain: string): Promise<DomainPricing> {
    try {
      // Try GoDaddy live pricing via their search page
      const livePricing = await this.scrapeGoDaddyPricing(domain);
      if (livePricing) {
        return {
          provider: 'GoDaddy',
          available: true,
          registrationPrice: livePricing.registration ?? undefined,
          renewalPrice: livePricing.renewal ?? undefined,
          currency: 'USD',
          url: `https://www.godaddy.com/domainsearch/find?checkAvail=1&domainToCheck=${domain}`,
          error: undefined
        };
      }

      throw new Error('No live pricing available');
    } catch (error) {
      return {
        provider: 'GoDaddy',
        available: false,
        currency: 'USD',
        url: `https://www.godaddy.com/domainsearch/find?checkAvail=1&domainToCheck=${domain}`,
        error: `Failed to get live pricing: ${error}`
      };
    }
  }

  private async checkNamecom(domain: string): Promise<DomainPricing> {
    try {
      // Try Name.com live API pricing
      const livePricing = await this.getNamecomLivePricing(domain);
      if (livePricing) {
        return {
          provider: 'Name.com',
          available: true,
          registrationPrice: livePricing.registration ?? undefined,
          renewalPrice: livePricing.renewal ?? undefined,
          currency: 'USD',
          url: `https://www.name.com/domain/search/${domain}`,
          error: undefined
        };
      }

      // Fallback to web scraping
      const scrapedPricing = await this.scrapeNamecomPricing(domain);
      if (scrapedPricing) {
        return {
          provider: 'Name.com',
          available: true,
          registrationPrice: scrapedPricing.registration ?? undefined,
          renewalPrice: scrapedPricing.renewal ?? undefined,
          currency: 'USD',
          url: `https://www.name.com/domain/search/${domain}`,
          error: 'Live pricing via web scraping'
        };
      }

      throw new Error('No live pricing available');
    } catch (error) {
      return {
        provider: 'Name.com',
        available: false,
        currency: 'USD',
        url: `https://www.name.com/domain/search/${domain}`,
        error: `Failed to get live pricing: ${error}`
      };
    }
  }

  // Live pricing from Cloudflare's pricing site (third-party service)
  private async getCloudflareLivePricing(tld?: string): Promise<{ registration: number | null; renewal: number | null } | null> {
    if (!tld) return null;
    
    try {
      // Use the third-party cfdomainpricing.com service
      const response = await axios.get(`https://cfdomainpricing.com/api/pricing/${tld}`, {
        timeout: this.timeout,
        headers: {
          'User-Agent': 'DOMAINLOOKER/1.0'
        }
      });

      if (response.data?.price !== undefined) {
        const price = parseFloat(response.data.price);
        return {
          registration: price || null,
          renewal: price || null // Cloudflare uses same price for registration and renewal
        };
      }
      
      return null;
    } catch (error) {
      console.log(`Failed to fetch live Cloudflare pricing for .${tld}: ${error}`);
      return null;
    }
  }

  // Live pricing from Namecheap via their search API endpoint
  private async scrapeNamecheapPricing(domain: string): Promise<{ registration: number | null; renewal: number | null } | null> {
    try {
      // Try their internal search API endpoint
      const response = await axios.post('https://www.namecheap.com/domains/registration/searchdomain/', {
        domain: domain,
        type: 'domain'
      }, {
        timeout: this.timeout,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-Requested-With': 'XMLHttpRequest'
        }
      });

      if (response.data && response.data.IsSuccess) {
        const domainData = response.data.Domains?.find((d: any) => d.DomainName === domain);
        if (domainData && domainData.Price) {
          return {
            registration: parseFloat(domainData.Price),
            renewal: parseFloat(domainData.RenewalPrice) || null
          };
        }
      }

      return null;
    } catch (error) {
      console.log(`Failed to get Namecheap API pricing for ${domain}: ${error}`);
      return null;
    }
  }

  // Live Namecheap API pricing (requires API access)
  private async getNamecheapLivePricing(domain: string): Promise<{ registration: number | null; renewal: number | null } | null> {
    // Namecheap API requires account with 20+ domains, $50+ balance, or $50+ spent
    // Since most users won't have this, we'll skip API and use scraping
    return null;
  }

  // Live pricing from GoDaddy via their search API
  private async scrapeGoDaddyPricing(domain: string): Promise<{ registration: number | null; renewal: number | null } | null> {
    try {
      // Try GoDaddy's internal search API
      const response = await axios.get(`https://api.godaddy.com/v1/domains/available?domain=${domain}&checkType=FAST&forTransfer=false`, {
        timeout: this.timeout,
        headers: {
          'User-Agent': 'DOMAINLOOKER/1.0',
          'Accept': 'application/json'
        }
      });

      if (response.data && response.data.available !== undefined) {
        // GoDaddy API returns pricing in micro-units, convert to dollars
        const price = response.data.price ? response.data.price / 1000000 : null;
        return price ? { registration: price, renewal: null } : null;
      }

      return null;
    } catch (error) {
      console.log(`Failed to get GoDaddy API pricing for ${domain}: ${error}`);
      return null;
    }
  }

  // Live Name.com API pricing
  private async getNamecomLivePricing(domain: string): Promise<{ registration: number | null; renewal: number | null } | null> {
    try {
      // Name.com has a public API for pricing, but it requires authentication
      // We'll try their pricing endpoint without auth first
      const response = await axios.get(`https://api.name.com/v4/domains/${domain}/pricing`, {
        timeout: this.timeout,
        headers: {
          'User-Agent': 'DOMAINLOOKER/1.0'
        }
      });

      if (response.data && response.data.registrationPrice) {
        return {
          registration: parseFloat(response.data.registrationPrice),
          renewal: parseFloat(response.data.renewalPrice) || null
        };
      }

      return null;
    } catch (error) {
      console.log(`Failed to get Name.com API pricing for ${domain}: ${error}`);
      return null;
    }
  }

  // Live pricing from Name.com via web scraping
  private async scrapeNamecomPricing(domain: string): Promise<{ registration: number | null; renewal: number | null } | null> {
    try {
      const response = await axios.get(`https://www.name.com/domain/search/${domain}`, {
        timeout: this.timeout,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
      });

      const html = response.data;
      const regexPatterns = [
        /\$(\d+\.?\d*)\s*\/?\s*1st\s*year/i,
        /\$(\d+\.?\d*)\s*\/?\s*first\s*year/i,
        /registration.*?\$(\d+\.?\d*)/i,
        /\$(\d+\.?\d*)\s*reg/i
      ];

      let registrationPrice = null;
      for (const pattern of regexPatterns) {
        const match = html.match(pattern);
        if (match) {
          registrationPrice = parseFloat(match[1]);
          break;
        }
      }

      return registrationPrice ? { registration: registrationPrice, renewal: null } : null;
    } catch (error) {
      console.log(`Failed to scrape Name.com pricing for ${domain}: ${error}`);
      return null;
    }
  }

  // Live API call to Porkbun for current pricing
  private async getPorkbunLivePricing(tld?: string): Promise<{ registration: number | null; renewal: number | null } | null> {
    if (!tld) return null;
    
    try {
      const response = await axios.get('https://api.porkbun.com/api/json/v3/pricing/get', {
        timeout: this.timeout,
        headers: {
          'User-Agent': 'DOMAINLOOKER/1.0'
        }
      });

      if (response.data?.status === 'SUCCESS' && response.data?.pricing) {
        const tldPricing = response.data.pricing[tld];
        if (tldPricing) {
          return {
            registration: parseFloat(tldPricing.registration) || null,
            renewal: parseFloat(tldPricing.renewal) || null
          };
        }
      }
      
      return null;
    } catch (error) {
      console.log(`Failed to fetch live Porkbun pricing for .${tld}: ${error}`);
      return null;
    }
  }

  // NO MORE ESTIMATES - Only live data or failure
}