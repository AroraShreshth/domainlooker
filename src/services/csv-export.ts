import { DomainInfo } from '../types/index.js';
import * as fs from 'fs';
import * as path from 'path';

export class CSVExportService {
  private csvData: string[] = [];

  constructor() {
    // CSV Header
    this.csvData.push([
      'Domain',
      'Registrar',
      'Registration Date',
      'Expiration Date',
      'Registrant Country',
      'Status',
      'Name Servers',
      'IPv4 Addresses',
      'IPv6 Addresses',
      'MX Records',
      'TXT Records',
      'SSL Issuer',
      'SSL Subject',
      'SSL Valid From',
      'SSL Valid To',
      'SSL Days Until Expiry',
      'SSL Valid',
      'Open Ports',
      'Services',
      'Subdomains Found',
      'Sample Subdomains',
      'Available for Registration',
      'Cheapest Registration Price',
      'Cheapest Renewal Price',
      'Best Registration Provider',
      'Best Renewal Provider',
      'All Pricing Data',
      'Threat Level',
      'Threats'
    ].join(','));
  }

  addDomain(domainInfo: DomainInfo): void {
    const {
      domain,
      whois,
      dns,
      ssl,
      network,
      subdomains,
      pricing
    } = domainInfo;

    // Process arrays and objects for CSV format
    const nameServers = whois?.nameServers?.join('; ') || '';
    const ipv4Addresses = dns?.a?.join('; ') || '';
    const ipv6Addresses = dns?.aaaa?.join('; ') || '';
    const mxRecords = dns?.mx?.map(mx => `${mx.priority} ${mx.exchange}`).join('; ') || '';
    const txtRecords = dns?.txt?.slice(0, 3).join('; ') || ''; // Limit TXT records
    const openPorts = network?.openPorts?.join('; ') || '';
    const services = network?.services?.map(s => `${s.port}:${s.service}`).join('; ') || '';
    const status = whois?.status?.join('; ') || '';
    const subdomainCount = subdomains?.totalFound?.toString() || '0';
    const sampleSubdomains = subdomains?.subdomains?.slice(0, 5).join('; ') || '';

    // Process pricing data
    const pricingData = this.processPricingData(pricing);

    // Threat assessment
    const threats = this.assessThreats(domainInfo);
    const threatLevel = this.getThreatLevel(threats);

    // Escape CSV values
    const csvRow = [
      this.escapeCSV(domain),
      this.escapeCSV(whois?.registrar || ''),
      this.escapeCSV(whois?.registrationDate || ''),
      this.escapeCSV(whois?.expirationDate || ''),
      this.escapeCSV(whois?.registrantCountry || ''),
      this.escapeCSV(status),
      this.escapeCSV(nameServers),
      this.escapeCSV(ipv4Addresses),
      this.escapeCSV(ipv6Addresses),
      this.escapeCSV(mxRecords),
      this.escapeCSV(txtRecords),
      this.escapeCSV(ssl?.issuer || ''),
      this.escapeCSV(ssl?.subject || ''),
      this.escapeCSV(ssl?.validFrom || ''),
      this.escapeCSV(ssl?.validTo || ''),
      this.escapeCSV(ssl?.daysUntilExpiry?.toString() || ''),
      this.escapeCSV(ssl?.isValid?.toString() || ''),
      this.escapeCSV(openPorts),
      this.escapeCSV(services),
      this.escapeCSV(subdomainCount),
      this.escapeCSV(sampleSubdomains),
      this.escapeCSV(pricingData.isAvailable),
      this.escapeCSV(pricingData.cheapestRegistration),
      this.escapeCSV(pricingData.cheapestRenewal),
      this.escapeCSV(pricingData.bestRegProvider),
      this.escapeCSV(pricingData.bestRenewalProvider),
      this.escapeCSV(pricingData.allPricing),
      this.escapeCSV(threatLevel),
      this.escapeCSV(threats.join('; '))
    ].join(',');

    this.csvData.push(csvRow);
  }

  private assessThreats(info: DomainInfo): string[] {
    const threats: string[] = [];

    // SSL certificate expiry
    if (info.ssl?.daysUntilExpiry !== undefined && info.ssl.daysUntilExpiry < 30) {
      threats.push(`SSL expires in ${info.ssl.daysUntilExpiry} days`);
    }

    // Missing SSL
    if (!info.ssl) {
      threats.push('No SSL certificate detected');
    }

    // Recently registered domains
    if (info.whois?.registrationDate) {
      const regDate = new Date(info.whois.registrationDate);
      const daysSinceReg = (Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24);
      
      if (daysSinceReg < 30) {
        threats.push('Domain registered recently');
      }
    }

    // Invalid SSL
    if (info.ssl && info.ssl.isValid === false) {
      threats.push('Invalid SSL certificate');
    }

    return threats;
  }

  private getThreatLevel(threats: string[]): string {
    if (threats.length === 0) return 'LOW';
    if (threats.some(t => t.includes('Invalid SSL') || t.includes('No SSL'))) return 'HIGH';
    if (threats.some(t => t.includes('expires'))) return 'MEDIUM';
    return 'LOW';
  }

  private processPricingData(pricing?: any): {
    isAvailable: string;
    cheapestRegistration: string;
    cheapestRenewal: string;
    bestRegProvider: string;
    bestRenewalProvider: string;
    allPricing: string;
  } {
    if (!pricing) {
      return {
        isAvailable: 'Unknown',
        cheapestRegistration: '',
        cheapestRenewal: '',
        bestRegProvider: '',
        bestRenewalProvider: '',
        allPricing: ''
      };
    }

    const validPricing = pricing.pricing?.filter((p: any) => p.available && p.registrationPrice) || [];
    
    if (validPricing.length === 0) {
      return {
        isAvailable: pricing.isAvailable ? 'Yes' : 'No',
        cheapestRegistration: '',
        cheapestRenewal: '',
        bestRegProvider: '',
        bestRenewalProvider: '',
        allPricing: ''
      };
    }

    // Find cheapest registration
    const cheapestReg = validPricing.reduce((prev: any, curr: any) => 
      (curr.registrationPrice || Infinity) < (prev.registrationPrice || Infinity) ? curr : prev
    );

    // Find cheapest renewal
    const cheapestRen = validPricing.reduce((prev: any, curr: any) => 
      (curr.renewalPrice || Infinity) < (prev.renewalPrice || Infinity) ? curr : prev
    );

    // Format all pricing data
    const allPricingText = validPricing.map((p: any) => 
      `${p.provider}: Reg $${p.registrationPrice?.toFixed(2) || 'N/A'} / Ren $${p.renewalPrice?.toFixed(2) || 'N/A'}`
    ).join(' | ');

    return {
      isAvailable: pricing.isAvailable ? 'Yes' : 'No',
      cheapestRegistration: `$${cheapestReg.registrationPrice?.toFixed(2) || 'N/A'}`,
      cheapestRenewal: `$${cheapestRen.renewalPrice?.toFixed(2) || 'N/A'}`,
      bestRegProvider: cheapestReg.provider || '',
      bestRenewalProvider: cheapestRen.provider || '',
      allPricing: allPricingText
    };
  }

  private escapeCSV(value: string): string {
    if (!value) return '';
    
    // Escape quotes and wrap in quotes if contains comma, quote, or newline
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    
    return value;
  }

  async exportToFile(filename: string): Promise<void> {
    const csvContent = this.csvData.join('\n');
    
    // Ensure the filename has .csv extension
    const csvFilename = filename.endsWith('.csv') ? filename : `${filename}.csv`;
    
    // Get absolute path
    const fullPath = path.resolve(csvFilename);
    
    try {
      await fs.promises.writeFile(fullPath, csvContent, 'utf8');
      console.log(`\n📊 CSV Export Complete: ${fullPath}`);
      console.log(`📈 Exported ${this.csvData.length - 1} domains with complete intelligence data`);
    } catch (error) {
      console.error(`❌ Failed to export CSV: ${error}`);
      throw error;
    }
  }

  getRowCount(): number {
    return this.csvData.length - 1; // Subtract header row
  }
}