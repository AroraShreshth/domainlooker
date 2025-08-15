import { DomainAvailabilityResult, DomainPricing } from '../types/index.js';
import * as fs from 'fs';
import * as path from 'path';

export class PricingExportService {
  private pricingData: DomainAvailabilityResult[] = [];

  addDomain(pricingResult: DomainAvailabilityResult): void {
    this.pricingData.push(pricingResult);
  }

  async exportPricingCSV(filename: string): Promise<void> {
    const csvData: string[] = [];
    
    // Enhanced pricing-focused CSV header
    csvData.push([
      'Domain',
      'TLD',
      'Available',
      'Checked At',
      'Provider',
      'Registration Price',
      'Renewal Price',
      'Currency',
      'Registration URL',
      'Data Source',
      'Error/Notes'
    ].join(','));

    // Process each domain's pricing data
    for (const domainResult of this.pricingData) {
      if (domainResult.pricing && domainResult.pricing.length > 0) {
        // Create a row for each provider
        for (const pricing of domainResult.pricing) {
          csvData.push([
            this.escapeCSV(domainResult.domain),
            this.escapeCSV(this.extractTLD(domainResult.domain)),
            this.escapeCSV(domainResult.isAvailable ? 'Yes' : 'No'),
            this.escapeCSV(domainResult.checkedAt.toISOString()),
            this.escapeCSV(pricing.provider),
            this.escapeCSV(pricing.registrationPrice ? `$${pricing.registrationPrice.toFixed(2)}` : 'N/A'),
            this.escapeCSV(pricing.renewalPrice ? `$${pricing.renewalPrice.toFixed(2)}` : 'N/A'),
            this.escapeCSV(pricing.currency),
            this.escapeCSV(pricing.url),
            this.escapeCSV(this.getDataSource(pricing)),
            this.escapeCSV(pricing.error || '')
          ].join(','));
        }
      } else {
        // Domain with no pricing data
        csvData.push([
          this.escapeCSV(domainResult.domain),
          this.escapeCSV(this.extractTLD(domainResult.domain)),
          this.escapeCSV(domainResult.isAvailable ? 'Yes' : 'No'),
          this.escapeCSV(domainResult.checkedAt.toISOString()),
          'No Data',
          'N/A',
          'N/A',
          'N/A',
          'N/A',
          'N/A',
          'No pricing providers available'
        ].join(','));
      }
    }

    const csvContent = csvData.join('\n');
    const csvFilename = filename.endsWith('.csv') ? filename : `${filename}.csv`;
    const fullPath = path.resolve(csvFilename);
    
    try {
      await fs.promises.writeFile(fullPath, csvContent, 'utf8');
      console.log(`\n📊 Pricing CSV Export Complete: ${fullPath}`);
      console.log(`📈 Exported pricing data for ${this.pricingData.length} domains across multiple providers`);
    } catch (error) {
      console.error(`❌ Failed to export pricing CSV: ${error}`);
      throw error;
    }
  }

  async exportPricingJSON(filename: string): Promise<void> {
    const jsonData = {
      exportMetadata: {
        generatedAt: new Date().toISOString(),
        totalDomains: this.pricingData.length,
        version: '1.0',
        description: 'Domain pricing comparison data across multiple registrars'
      },
      pricingComparison: this.pricingData.map(domain => ({
        domain: domain.domain,
        tld: this.extractTLD(domain.domain),
        availability: {
          isAvailable: domain.isAvailable,
          checkedAt: domain.checkedAt.toISOString()
        },
        providers: domain.pricing.map(pricing => ({
          name: pricing.provider,
          available: pricing.available,
          pricing: {
            registration: {
              amount: pricing.registrationPrice,
              currency: pricing.currency,
              formatted: pricing.registrationPrice ? `${pricing.currency} ${pricing.registrationPrice.toFixed(2)}` : null
            },
            renewal: {
              amount: pricing.renewalPrice,
              currency: pricing.currency,
              formatted: pricing.renewalPrice ? `${pricing.currency} ${pricing.renewalPrice.toFixed(2)}` : null
            }
          },
          metadata: {
            url: pricing.url,
            dataSource: this.getDataSource(pricing),
            error: pricing.error || null,
            isLiveData: !pricing.error?.includes('fallback')
          }
        })),
        analysis: this.analyzePricing(domain.pricing)
      })),
      summary: this.generateSummary()
    };

    const jsonFilename = filename.endsWith('.json') ? filename : `${filename}.json`;
    const fullPath = path.resolve(jsonFilename);
    
    try {
      await fs.promises.writeFile(fullPath, JSON.stringify(jsonData, null, 2), 'utf8');
      console.log(`\n📋 Pricing JSON Export Complete: ${fullPath}`);
      console.log(`📊 Exported structured pricing analysis for ${this.pricingData.length} domains`);
    } catch (error) {
      console.error(`❌ Failed to export pricing JSON: ${error}`);
      throw error;
    }
  }

  private analyzePricing(pricing: DomainPricing[]) {
    const validPricing = pricing.filter(p => p.available && p.registrationPrice);
    
    if (validPricing.length === 0) {
      return {
        cheapestRegistration: null,
        cheapestRenewal: null,
        priceRange: null,
        avgRegistrationPrice: null,
        avgRenewalPrice: null,
        providerCount: 0
      };
    }

    const regPrices = validPricing.map(p => p.registrationPrice!).filter(p => p > 0);
    const renewalPrices = validPricing.map(p => p.renewalPrice!).filter(p => p > 0);

    const cheapestReg = validPricing.reduce((prev, curr) => 
      (curr.registrationPrice || Infinity) < (prev.registrationPrice || Infinity) ? curr : prev
    );

    const cheapestRenewal = validPricing.reduce((prev, curr) => 
      (curr.renewalPrice || Infinity) < (prev.renewalPrice || Infinity) ? curr : prev
    );

    return {
      cheapestRegistration: {
        provider: cheapestReg.provider,
        price: cheapestReg.registrationPrice,
        currency: cheapestReg.currency
      },
      cheapestRenewal: {
        provider: cheapestRenewal.provider,
        price: cheapestRenewal.renewalPrice,
        currency: cheapestRenewal.currency
      },
      priceRange: {
        registration: {
          min: Math.min(...regPrices),
          max: Math.max(...regPrices),
          spread: Math.max(...regPrices) - Math.min(...regPrices)
        },
        renewal: renewalPrices.length > 0 ? {
          min: Math.min(...renewalPrices),
          max: Math.max(...renewalPrices),
          spread: Math.max(...renewalPrices) - Math.min(...renewalPrices)
        } : null
      },
      avgRegistrationPrice: regPrices.length > 0 ? regPrices.reduce((a, b) => a + b, 0) / regPrices.length : null,
      avgRenewalPrice: renewalPrices.length > 0 ? renewalPrices.reduce((a, b) => a + b, 0) / renewalPrices.length : null,
      providerCount: validPricing.length
    };
  }

  private generateSummary() {
    const allPricing = this.pricingData.flatMap(d => d.pricing);
    const providers = [...new Set(allPricing.map(p => p.provider))];
    const liveDataCount = allPricing.filter(p => !p.error?.includes('fallback')).length;
    const fallbackCount = allPricing.filter(p => p.error?.includes('fallback')).length;

    return {
      totalDomains: this.pricingData.length,
      totalProviders: providers.length,
      providers: providers,
      dataQuality: {
        liveData: liveDataCount,
        fallbackData: fallbackCount,
        liveDataPercentage: allPricing.length > 0 ? (liveDataCount / allPricing.length * 100).toFixed(1) : '0'
      },
      availableDomains: this.pricingData.filter(d => d.isAvailable).length,
      registeredDomains: this.pricingData.filter(d => !d.isAvailable).length
    };
  }

  private extractTLD(domain: string): string {
    return domain.split('.').pop()?.toLowerCase() || '';
  }

  private getDataSource(pricing: DomainPricing): string {
    if (pricing.error?.includes('fallback')) return 'Fallback Estimate';
    if (pricing.error?.includes('API')) return 'API Error';
    if (pricing.provider === 'Porkbun' && !pricing.error) return 'Live API';
    if (pricing.provider === 'Cloudflare' && !pricing.error) return 'Third-party API';
    return 'Estimate';
  }

  private escapeCSV(value: string): string {
    if (!value) return '';
    
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    
    return value;
  }

  getDataCount(): number {
    return this.pricingData.length;
  }
}