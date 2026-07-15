// Structured schema for the JSON export produced by `domainlooker --export-json`.

export interface DomainAnalysisResponse {
  meta: ResponseMetadata;
  data: DomainAnalysisData[];
}

export interface ResponseMetadata {
  version: string;
  timestamp: string;
  requestId: string;
  executionTimeMs: number;
  totalDomains: number;
  options: AnalysisOptions;
}

export interface AnalysisOptions {
  includeSubdomains: boolean;
  includeNetworkScan: boolean;
  quickScan: boolean;
  verbose: boolean;
}

export interface DomainAnalysisData {
  domain: string;
  status: 'success' | 'partial' | 'failed';
  timestamp: string;
  executionTimeMs: number;
  
  // Per-source results
  whois: WhoisAnalysis | null;
  dns: DnsAnalysis | null;
  ssl: SslAnalysis | null;
  network: NetworkAnalysis | null;
  subdomains: SubdomainAnalysis | null;

  // Rule-based checks
  threatAssessment: ThreatAssessment;

  // Which method produced each block
  sources: DataSources;
}

export interface WhoisAnalysis {
  status: 'success' | 'failed' | 'not_available';
  data: {
    registrar?: string;
    registrationDate?: string;
    expirationDate?: string;
    registrantCountry?: string;
    nameServers?: string[];
    status?: string[];
    daysUntilExpiry?: number;
  } | null;
  error?: string;
}

export interface DnsAnalysis {
  status: 'success' | 'partial' | 'failed';
  data: {
    records: {
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
    };
    summary: {
      totalRecords: number;
      recordTypes: string[];
      hasIpv4: boolean;
      hasIpv6: boolean;
      hasMail: boolean;
    };
  } | null;
  error?: string;
}

export interface SslAnalysis {
  status: 'success' | 'failed' | 'no_certificate';
  data: {
    certificate: {
      subject: string;
      issuer: string;
      validFrom: string;
      validTo: string;
      serialNumber: string;
      fingerprint: string;
      signatureAlgorithm?: string;
    };
    validation: {
      isValid: boolean;
      daysUntilExpiry: number;
      isExpired: boolean;
      isSelfSigned: boolean;
    };
    security: {
      keySize?: number;
      protocol?: string;
      vulnerabilities?: string[];
    };
  } | null;
  error?: string;
}

export interface NetworkAnalysis {
  status: 'success' | 'partial' | 'failed' | 'skipped';
  data: {
    ports: {
      open: number[];
      filtered: number[];
      total: number;
    };
    services: Array<{
      port: number;
      protocol: string;
      service: string;
      version?: string;
      confidence: 'high' | 'medium' | 'low';
    }>;
    summary: {
      totalOpenPorts: number;
      commonServices: string[];
      unusualPorts: number[];
    };
  } | null;
  error?: string;
}

export interface SubdomainAnalysis {
  status: 'success' | 'partial' | 'failed' | 'skipped';
  data: {
    subdomains: string[];
    sources: {
      certificateTransparency: string[];
      commonNames: string[];
    };
    statistics: {
      total: number;
      bySource: { [source: string]: number };
      patterns: { [pattern: string]: number };
      depthAnalysis: { [depth: number]: number };
    };
  } | null;
  error?: string;
}

export interface ThreatAssessment {
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
  riskScore: number; // 0-100
  threats: ThreatIndicator[];
  recommendations: string[];
  summary: {
    criticalIssues: number;
    warnings: number;
    informational: number;
  };
}

export interface ThreatIndicator {
  type: 'ssl_expiry' | 'missing_ssl' | 'recent_registration' | 'open_ports';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  recommendation?: string;
  evidence?: any;
}

export interface DataSources {
  whois: string[];
  dns: string[];
  ssl: string[];
  network: string[];
  subdomains: string[];
  threatIntelligence: string[];
}