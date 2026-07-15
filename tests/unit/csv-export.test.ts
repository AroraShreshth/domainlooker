import { CSVExportService } from '../../src/services/csv-export';
import { mockDomainInfo, mockFailedDomainInfo } from '../fixtures/mock-data';
import * as fs from 'fs';
import * as path from 'path';

// Mock fs.promises
jest.mock('fs', () => ({
  promises: {
    writeFile: jest.fn()
  }
}));

describe('CSVExportService', () => {
  let csvExporter: CSVExportService;

  beforeEach(() => {
    csvExporter = new CSVExportService();
    jest.clearAllMocks();
  });

  describe('addDomain', () => {
    it('should add a domain to the CSV data', () => {
      csvExporter.addDomain(mockDomainInfo);
      expect(csvExporter.getRowCount()).toBe(1);
    });

    it('should handle multiple domains', () => {
      csvExporter.addDomain(mockDomainInfo);
      csvExporter.addDomain(mockFailedDomainInfo);
      expect(csvExporter.getRowCount()).toBe(2);
    });
  });

  describe('exportToFile', () => {
    beforeEach(() => {
      csvExporter.addDomain(mockDomainInfo);
    });

    it('should write CSV to file with correct filename', async () => {
      const filename = 'test-export';
      await csvExporter.exportToFile(filename);
      
      expect(fs.promises.writeFile).toHaveBeenCalledWith(
        path.resolve('test-export.csv'),
        expect.stringContaining('Domain,Registrar'),
        'utf8'
      );
    });

    it('should handle filename with .csv extension', async () => {
      const filename = 'test-export.csv';
      await csvExporter.exportToFile(filename);
      
      expect(fs.promises.writeFile).toHaveBeenCalledWith(
        path.resolve('test-export.csv'),
        expect.any(String),
        'utf8'
      );
    });

    it('should include CSV headers', async () => {
      await csvExporter.exportToFile('test');
      
      const writeCall = (fs.promises.writeFile as jest.Mock).mock.calls[0];
      const csvContent = writeCall[1];
      
      expect(csvContent).toContain('Domain,Registrar,Registration Date');
      expect(csvContent).toContain('IPv4 Addresses,IPv6 Addresses');
      expect(csvContent).toContain('SSL Issuer,SSL Subject');
    });

    it('should include domain data in CSV format', async () => {
      await csvExporter.exportToFile('test');
      
      const writeCall = (fs.promises.writeFile as jest.Mock).mock.calls[0];
      const csvContent = writeCall[1];
      
      expect(csvContent).toContain('example.com');
      expect(csvContent).toContain('Example Registrar Inc.');
      expect(csvContent).toContain('192.0.2.1; 192.0.2.2');
    });

    it('should properly escape CSV values', async () => {
      const domainWithCommas = {
        ...mockDomainInfo,
        whois: {
          ...mockDomainInfo.whois!,
          registrar: 'Test, Inc. "With Quotes"'
        }
      };
      
      csvExporter.addDomain(domainWithCommas);
      await csvExporter.exportToFile('test');
      
      const writeCall = (fs.promises.writeFile as jest.Mock).mock.calls[0];
      const csvContent = writeCall[1];
      
      expect(csvContent).toContain('"Test, Inc. ""With Quotes"""');
    });
  });

  describe('getRowCount', () => {
    it('should return correct count of domains', () => {
      expect(csvExporter.getRowCount()).toBe(0);
      
      csvExporter.addDomain(mockDomainInfo);
      expect(csvExporter.getRowCount()).toBe(1);
      
      csvExporter.addDomain(mockFailedDomainInfo);
      expect(csvExporter.getRowCount()).toBe(2);
    });
  });

  describe('CSV content validation', () => {
    it('should handle domains with missing data gracefully', async () => {
      csvExporter.addDomain(mockFailedDomainInfo);
      await csvExporter.exportToFile('test');
      
      const writeCall = (fs.promises.writeFile as jest.Mock).mock.calls[0];
      const csvContent = writeCall[1];
      
      expect(csvContent).toContain('nonexistent-test-domain-12345.invalid');
      // Missing fields are rendered as empty CSV cells
      expect(csvContent).toContain('nonexistent-test-domain-12345.invalid,,');
    });

    it('should format threat assessment correctly', async () => {
      await csvExporter.exportToFile('test');
      
      const writeCall = (fs.promises.writeFile as jest.Mock).mock.calls[0];
      const csvContent = writeCall[1];
      
      // Should contain threat assessment column
      expect(csvContent).toContain('Threat Level');
    });
  });
});