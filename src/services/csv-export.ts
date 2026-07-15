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
      subdomains
    } = domainInfo;

    // Process arrays and objects for CSV format
    const nameServers = whois?.nameServers?.join('; ') || '';
    const ipv4Addresses = dns?.a?.join('; ') || '';
    const ipv6Addresses = dns?.aaaa?.join('; ') || '';
    // Skip "null MX" (RFC 7505) entries whose exchange is empty or ".".
    const mxRecords = dns?.mx
      ?.filter(mx => mx.exchange && mx.exchange !== '.')
      .map(mx => `${mx.priority} ${mx.exchange}`)
      .join('; ') || '';
    const txtRecords = dns?.txt?.slice(0, 3).join('; ') || ''; // Limit TXT records
    const openPorts = network?.openPorts?.join('; ') || '';
    const services = network?.services?.map(s => `${s.port}:${s.service}`).join('; ') || '';
    const status = whois?.status?.join('; ') || '';
    const subdomainCount = subdomains?.totalFound?.toString() || '0';
    const sampleSubdomains = subdomains?.subdomains?.slice(0, 5).join('; ') || '';

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
      console.log(`\nCSV written to ${fullPath} (${this.csvData.length - 1} domain(s))`);
    } catch (error) {
      console.error(`Failed to write CSV: ${error}`);
      throw error;
    }
  }

  getRowCount(): number {
    return this.csvData.length - 1; // Subtract header row
  }
}