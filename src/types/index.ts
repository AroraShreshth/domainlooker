export interface DomainInfo {
  domain: string;
  whois?: WhoisData;
  dns?: DNSData;
  ssl?: SSLData;
  security?: SecurityData;
  network?: NetworkData;
  subdomains?: SubdomainData;
  pricing?: DomainAvailabilityResult;
}

export interface SubdomainData {
  subdomains: string[];
  sources: {
    dnsEnumeration: string[];
    certificateTransparency: string[];
    commonNames: string[];
  };
  totalFound: number;
}

export interface WhoisData {
  registrar?: string;
  registrationDate?: string;
  expirationDate?: string;
  nameServers?: string[];
  registrantCountry?: string;
  status?: string[];
}

export interface DNSData {
  a?: string[];
  aaaa?: string[];
  mx?: Array<{ priority: number; exchange: string }>;
  ns?: string[];
  txt?: string[];
  cname?: string[];
  soa?: {
    primary: string;
    admin: string;
    serial: number;
    refresh: number;
    retry: number;
    expiration: number;
    minimum: number;
  };
}

export interface SSLData {
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  fingerprint?: string;
  serialNumber?: string;
  signatureAlgorithm?: string;
  keySize?: number;
  isValid?: boolean;
  daysUntilExpiry?: number;
}

export interface SecurityData {
  threatLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  blacklisted?: boolean;
  malwareDetected?: boolean;
  phishingRisk?: boolean;
  reputation?: number;
}

export interface NetworkData {
  openPorts?: number[];
  services?: Array<{
    port: number;
    protocol: string;
    service: string;
    version?: string;
  }>;
  location?: {
    country: string;
    city: string;
    coordinates?: [number, number];
  };
}

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

export interface InspectionOptions {
  verbose?: boolean;
  quick?: boolean;
  banner?: boolean;
  exportCsv?: string;
  exportJson?: string;
  subdomains?: boolean;
  checkPricing?: boolean;
}