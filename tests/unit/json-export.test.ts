import { JsonExportService } from '../../src/services/json-export';
import { mockDomainInfo, mockFailedDomainInfo } from '../fixtures/mock-data';
import { InspectionOptions } from '../../src/types';
import * as fs from 'fs';
import * as path from 'path';

// Mock fs.promises
jest.mock('fs', () => ({
  promises: {
    writeFile: jest.fn()
  }
}));

describe('JsonExportService', () => {
  let jsonExporter: JsonExportService;
  const mockOptions: InspectionOptions = {
    verbose: false,
    quick: false,
    subdomains: true
  };

  beforeEach(() => {
    jsonExporter = new JsonExportService(mockOptions);
    jest.clearAllMocks();
  });

  describe('addDomain', () => {
    it('should add a domain to the export data', () => {
      jsonExporter.addDomain(mockDomainInfo);
      
      const result = jsonExporter.getStructuredData();
      expect(result.data).toHaveLength(1);
      expect(result.data[0].domain).toBe('example.com');
      expect(result.data[0].status).toBe('success');
    });

    it('should handle multiple domains', () => {
      jsonExporter.addDomain(mockDomainInfo);
      jsonExporter.addDomain(mockFailedDomainInfo);
      
      const result = jsonExporter.getStructuredData();
      expect(result.data).toHaveLength(2);
      expect(result.meta.totalDomains).toBe(2);
    });
  });

  describe('getStructuredData', () => {
    beforeEach(() => {
      jsonExporter.addDomain(mockDomainInfo);
    });

    it('should return valid response metadata', () => {
      const result = jsonExporter.getStructuredData();
      
      expect(result.meta.version).toBe('1.0.0');
      expect(result.meta.totalDomains).toBe(1);
      expect(result.meta.requestId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
      expect(typeof result.meta.executionTimeMs).toBe('number');
      expect(result.meta.options).toEqual({
        includeSubdomains: true,
        includeNetworkScan: true,
        quickScan: false,
        verbose: false
      });
    });

    it('should transform WHOIS data correctly', () => {
      const result = jsonExporter.getStructuredData();
      const whoisAnalysis = result.data[0].whois!;

      expect(whoisAnalysis.status).toBe('success');
      expect(whoisAnalysis.data?.registrar).toBe('Example Registrar Inc.');
      expect(whoisAnalysis.data?.registrantCountry).toBe('US');
      expect(typeof whoisAnalysis.data?.daysUntilExpiry).toBe('number');
    });

    it('should transform DNS data correctly', () => {
      const result = jsonExporter.getStructuredData();
      const dnsAnalysis = result.data[0].dns!;

      expect(dnsAnalysis.status).toBe('success');
      expect(dnsAnalysis.data?.records.a).toEqual(['192.0.2.1', '192.0.2.2']);
      expect(dnsAnalysis.data?.summary.hasIpv4).toBe(true);
      expect(dnsAnalysis.data?.summary.hasIpv6).toBe(true);
      expect(dnsAnalysis.data?.summary.hasMail).toBe(true);
    });

    it('should transform SSL data correctly', () => {
      const result = jsonExporter.getStructuredData();
      const sslAnalysis = result.data[0].ssl!;

      expect(sslAnalysis.status).toBe('success');
      expect(sslAnalysis.data?.certificate.subject).toBe('CN=example.com');
      expect(sslAnalysis.data?.validation.isValid).toBe(true);
      expect(sslAnalysis.data?.validation.daysUntilExpiry).toBe(180);
    });

    it('should perform threat assessment', () => {
      const result = jsonExporter.getStructuredData();
      const threatAssessment = result.data[0].threatAssessment;
      
      expect(threatAssessment.overallRisk).toBe('low');
      expect(typeof threatAssessment.riskScore).toBe('number');
      expect(Array.isArray(threatAssessment.threats)).toBe(true);
      expect(Array.isArray(threatAssessment.recommendations)).toBe(true);
    });

    it('should track data sources', () => {
      const result = jsonExporter.getStructuredData();
      const sources = result.data[0].sources;
      
      expect(sources.whois).toContain('WHOIS Registry');
      expect(sources.dns).toContain('System DNS Resolver');
      expect(sources.ssl).toContain('TLS Connection');
      expect(sources.network).toContain('TCP Port Scan');
      expect(sources.threatIntelligence).toContain('Internal Analysis Engine');
    });
  });

  describe('exportToFile', () => {
    beforeEach(() => {
      jsonExporter.addDomain(mockDomainInfo);
    });

    it('should write JSON to file with correct filename', async () => {
      const filename = 'test-export';
      await jsonExporter.exportToFile(filename);
      
      expect(fs.promises.writeFile).toHaveBeenCalledWith(
        path.resolve('test-export.json'),
        expect.stringContaining('"domain": "example.com"'),
        'utf8'
      );
    });

    it('should handle filename with .json extension', async () => {
      const filename = 'test-export.json';
      await jsonExporter.exportToFile(filename);
      
      expect(fs.promises.writeFile).toHaveBeenCalledWith(
        path.resolve('test-export.json'),
        expect.any(String),
        'utf8'
      );
    });

    it('should export valid JSON structure', async () => {
      const filename = 'test-export';
      await jsonExporter.exportToFile(filename);
      
      const writeCall = (fs.promises.writeFile as jest.Mock).mock.calls[0];
      const jsonContent = writeCall[1];
      
      expect(() => JSON.parse(jsonContent)).not.toThrow();
      
      const parsed = JSON.parse(jsonContent);
      expect(parsed.meta).toBeDefined();
      expect(parsed.data).toBeDefined();
      expect(Array.isArray(parsed.data)).toBe(true);
    });
  });

  describe('threat assessment scoring', () => {
    it('should assign high risk for missing SSL', () => {
      const domainWithoutSSL = { ...mockDomainInfo, ssl: undefined };
      jsonExporter.addDomain(domainWithoutSSL);
      
      const result = jsonExporter.getStructuredData();
      const threats = result.data[0].threatAssessment.threats;
      
      expect(threats.some(t => t.type === 'missing_ssl')).toBe(true);
      expect(result.data[0].threatAssessment.riskScore).toBeGreaterThan(0);
    });

    it('should detect expiring SSL certificates', () => {
      const domainWithExpiringSS = {
        ...mockDomainInfo,
        ssl: { ...mockDomainInfo.ssl!, daysUntilExpiry: 5 }
      };
      jsonExporter.addDomain(domainWithExpiringSS);
      
      const result = jsonExporter.getStructuredData();
      const threats = result.data[0].threatAssessment.threats;
      
      expect(threats.some(t => t.type === 'ssl_expiry')).toBe(true);
    });

    it('should detect recently registered domains', () => {
      const recentDomain = {
        ...mockDomainInfo,
        whois: {
          ...mockDomainInfo.whois!,
          registrationDate: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString() // 10 days ago
        }
      };
      jsonExporter.addDomain(recentDomain);
      
      const result = jsonExporter.getStructuredData();
      const threats = result.data[0].threatAssessment.threats;
      
      expect(threats.some(t => t.type === 'recent_registration')).toBe(true);
    });
  });

  describe('getAnalysisCount', () => {
    it('should return correct count of analyzed domains', () => {
      expect(jsonExporter.getAnalysisCount()).toBe(0);
      
      jsonExporter.addDomain(mockDomainInfo);
      expect(jsonExporter.getAnalysisCount()).toBe(1);
      
      jsonExporter.addDomain(mockFailedDomainInfo);
      expect(jsonExporter.getAnalysisCount()).toBe(2);
    });
  });
});