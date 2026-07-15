export interface DomainInfo {
  domain: string;
  whois?: WhoisData;
  dns?: DNSData;
  ssl?: SSLData;
  network?: NetworkData;
  subdomains?: SubdomainData;
}

export interface SubdomainData {
  subdomains: string[];
  sources: {
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

export interface InspectionOptions {
  verbose?: boolean;
  quick?: boolean;
  exportCsv?: string;
  exportJson?: string;
  subdomains?: boolean;
}