import { JsonExportService } from '../../src/services/json-export';
import { CSVExportService } from '../../src/services/csv-export';
import { DNSService } from '../../src/services/dns';
import { WhoisService } from '../../src/services/whois';
import { SSLService } from '../../src/services/ssl';
import { NetworkService } from '../../src/services/network';
import { SubdomainService } from '../../src/services/subdomain';
import { DomainCollector, hasWhoisData, hasDnsData } from '../../src/core/collector';

describe('Core Services Instantiation', () => {
  describe('Service Creation', () => {
    it('should create JsonExportService', () => {
      const service = new JsonExportService();
      expect(service).toBeInstanceOf(JsonExportService);
    });

    it('should create CSVExportService', () => {
      const service = new CSVExportService();
      expect(service).toBeInstanceOf(CSVExportService);
    });

    it('should create DNSService', () => {
      const service = new DNSService();
      expect(service).toBeInstanceOf(DNSService);
    });

    it('should create WhoisService', () => {
      const service = new WhoisService();
      expect(service).toBeInstanceOf(WhoisService);
    });

    it('should create SSLService', () => {
      const service = new SSLService();
      expect(service).toBeInstanceOf(SSLService);
    });

    it('should create NetworkService', () => {
      const service = new NetworkService();
      expect(service).toBeInstanceOf(NetworkService);
    });

    it('should create SubdomainService', () => {
      const service = new SubdomainService();
      expect(service).toBeInstanceOf(SubdomainService);
    });

    it('should create DomainCollector with all lookup methods', () => {
      const collector = new DomainCollector();
      expect(collector).toBeInstanceOf(DomainCollector);
      for (const method of ['collect', 'whois', 'dns', 'ssl', 'ports', 'subdomains'] as const) {
        expect(typeof collector[method]).toBe('function');
      }
    });
  });

  describe('Collector predicates', () => {
    it('hasWhoisData is false for empty/undefined, true for populated', () => {
      expect(hasWhoisData(undefined)).toBe(false);
      expect(hasWhoisData(null)).toBe(false);
      expect(hasWhoisData({})).toBe(false);
      expect(hasWhoisData({ registrar: 'X' })).toBe(true);
    });

    it('hasDnsData is false for empty/undefined, true for populated', () => {
      expect(hasDnsData(undefined)).toBe(false);
      expect(hasDnsData({})).toBe(false);
      expect(hasDnsData({ a: ['1.2.3.4'] })).toBe(true);
    });
  });

  describe('Service Methods', () => {
    it('should have expected methods on JsonExportService', () => {
      const service = new JsonExportService();
      expect(typeof service.addDomain).toBe('function');
      expect(typeof service.exportToFile).toBe('function');
      expect(typeof service.getStructuredData).toBe('function');
      expect(typeof service.getAnalysisCount).toBe('function');
    });

    it('should have expected methods on CSVExportService', () => {
      const service = new CSVExportService();
      expect(typeof service.addDomain).toBe('function');
      expect(typeof service.exportToFile).toBe('function');
      expect(typeof service.getRowCount).toBe('function');
    });

    it('should have expected methods on DNSService', () => {
      const service = new DNSService();
      expect(typeof service.lookup).toBe('function');
    });

    it('should have expected methods on WhoisService', () => {
      const service = new WhoisService();
      expect(typeof service.lookup).toBe('function');
    });

    it('should have expected methods on SSLService', () => {
      const service = new SSLService();
      expect(typeof service.getCertificate).toBe('function');
    });

    it('should have expected methods on NetworkService', () => {
      const service = new NetworkService();
      expect(typeof service.getNetworkInfo).toBe('function');
    });

    it('should have expected methods on SubdomainService', () => {
      const service = new SubdomainService();
      expect(typeof service.discoverSubdomains).toBe('function');
    });
  });

  describe('Export Services Basic Operations', () => {
    it('should start with empty data in JsonExportService', () => {
      const service = new JsonExportService();
      expect(service.getAnalysisCount()).toBe(0);
    });

    it('should start with empty data in CSVExportService', () => {
      const service = new CSVExportService();
      expect(service.getRowCount()).toBe(0); // Header row not counted
    });

    it('should generate valid metadata in JsonExportService', () => {
      const service = new JsonExportService();
      const data = service.getStructuredData();
      
      expect(data).toHaveProperty('meta');
      expect(data).toHaveProperty('data');
      expect(data.meta).toHaveProperty('version');
      expect(data.meta).toHaveProperty('timestamp');
      expect(data.meta).toHaveProperty('requestId');
      expect(typeof data.meta.executionTimeMs).toBe('number');
      expect(Array.isArray(data.data)).toBe(true);
    });
  });
});