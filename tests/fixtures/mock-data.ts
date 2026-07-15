import { DomainInfo, WhoisData, DNSData, SSLData, NetworkData, SubdomainData } from '../../src/types';

export const mockWhoisData: WhoisData = {
  registrar: 'Example Registrar Inc.',
  registrationDate: '2010-01-01T00:00:00Z',
  expirationDate: '2026-01-01T00:00:00Z',
  registrantCountry: 'US',
  nameServers: ['ns1.example.com', 'ns2.example.com'],
  status: ['clientUpdateProhibited']
};

export const mockDNSData: DNSData = {
  a: ['192.0.2.1', '192.0.2.2'],
  aaaa: ['2001:db8::1'],
  mx: [{ priority: 10, exchange: 'mail.example.com' }],
  ns: ['ns1.example.com', 'ns2.example.com'],
  txt: ['v=spf1 include:_spf.example.com ~all'],
  soa: {
    primary: 'ns1.example.com',
    admin: 'admin.example.com',
    serial: 2023010101,
    refresh: 3600,
    retry: 1800,
    expiration: 604800,
    minimum: 86400
  }
};

export const mockSSLData: SSLData = {
  issuer: 'CN=Example CA',
  subject: 'CN=example.com',
  validFrom: '2025-01-01T00:00:00Z',
  validTo: '2026-01-01T00:00:00Z',
  fingerprint: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD',
  serialNumber: '12345678901234567890',
  signatureAlgorithm: 'sha256WithRSAEncryption',
  keySize: 2048,
  isValid: true,
  daysUntilExpiry: 180
};

export const mockNetworkData: NetworkData = {
  openPorts: [80, 443],
  services: [
    {
      port: 80,
      protocol: 'TCP',
      service: 'HTTP'
    },
    {
      port: 443,
      protocol: 'TCP',
      service: 'HTTPS'
    }
  ]
};

export const mockSubdomainData: SubdomainData = {
  subdomains: ['www.example.com', 'mail.example.com', 'ftp.example.com'],
  sources: {
    certificateTransparency: ['mail.example.com', 'www.example.com'],
    commonNames: ['ftp.example.com']
  },
  totalFound: 3
};

export const mockDomainInfo: DomainInfo = {
  domain: 'example.com',
  whois: mockWhoisData,
  dns: mockDNSData,
  ssl: mockSSLData,
  network: mockNetworkData,
  subdomains: mockSubdomainData
};

export const mockFailedDomainInfo: DomainInfo = {
  domain: 'nonexistent-test-domain-12345.invalid',
  whois: undefined,
  dns: undefined,
  ssl: undefined,
  network: undefined,
  subdomains: undefined
};