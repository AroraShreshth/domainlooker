import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { DomainInfo, InspectionOptions } from '../types/index.js';
import { 
  DomainAnalysisResponse, 
  DomainAnalysisData, 
  ResponseMetadata,
  WhoisAnalysis,
  DnsAnalysis,
  SslAnalysis,
  NetworkAnalysis,
  SubdomainAnalysis,
  ThreatAssessment,
  ThreatIndicator,
  DataSources
} from '../types/api-schema.js';

export class JsonExportService {
  private domains: DomainAnalysisData[] = [];
  private startTime: number = Date.now();
  private requestId: string = randomUUID();
  private options: InspectionOptions;

  constructor(options: InspectionOptions = {}) {
    this.options = options;
  }

  addDomain(domainInfo: DomainInfo): void {
    const analysisData = this.transformDomainData(domainInfo);
    this.domains.push(analysisData);
  }

  private transformDomainData(domainInfo: DomainInfo): DomainAnalysisData {
    const executionStart = Date.now();
    
    return {
      domain: domainInfo.domain,
      status: this.determineOverallStatus(domainInfo),
      timestamp: new Date().toISOString(),
      executionTimeMs: Date.now() - executionStart,
      
      whois: this.transformWhoisData(domainInfo.whois),
      dns: this.transformDnsData(domainInfo.dns),
      ssl: this.transformSslData(domainInfo.ssl),
      network: this.transformNetworkData(domainInfo.network),
      subdomains: this.transformSubdomainData(domainInfo.subdomains),
      
      threatAssessment: this.performThreatAssessment(domainInfo),
      sources: this.collectDataSources(domainInfo)
    };
  }

  private determineOverallStatus(domainInfo: DomainInfo): 'success' | 'partial' | 'failed' {
    const successfulServices = [
      !!domainInfo.whois,
      !!domainInfo.dns,
      !!domainInfo.ssl,
      !!domainInfo.network,
      !!domainInfo.subdomains
    ].filter(Boolean).length;

    if (successfulServices >= 3) return 'success';
    if (successfulServices >= 1) return 'partial';
    return 'failed';
  }

  private transformWhoisData(whois: any): WhoisAnalysis {
    if (!whois) {
      return {
        status: 'not_available',
        data: null,
        error: 'WHOIS data not available'
      };
    }

    const daysUntilExpiry = whois.expirationDate ? 
      Math.ceil((new Date(whois.expirationDate).getTime() - Date.now()) / (1000 * 60 * 60 * 24)) : 
      undefined;

    return {
      status: 'success',
      data: {
        registrar: whois.registrar,
        registrationDate: whois.registrationDate,
        expirationDate: whois.expirationDate,
        registrantCountry: whois.registrantCountry,
        nameServers: whois.nameServers,
        status: whois.status,
        daysUntilExpiry
      }
    };
  }

  private transformDnsData(dns: any): DnsAnalysis {
    if (!dns) {
      return {
        status: 'failed',
        data: null,
        error: 'DNS lookup failed'
      };
    }

    const records = {
      a: dns.a,
      aaaa: dns.aaaa,
      mx: dns.mx,
      ns: dns.ns,
      txt: dns.txt,
      cname: dns.cname,
      soa: dns.soa
    };

    const recordTypes = Object.keys(records).filter(key => records[key as keyof typeof records]);
    const totalRecords = recordTypes.reduce((sum, type) => {
      const record = records[type as keyof typeof records];
      return sum + (Array.isArray(record) ? record.length : (record ? 1 : 0));
    }, 0);

    return {
      status: 'success',
      data: {
        records,
        summary: {
          totalRecords,
          recordTypes,
          hasIpv4: !!(dns.a && dns.a.length > 0),
          hasIpv6: !!(dns.aaaa && dns.aaaa.length > 0),
          hasMail: !!(dns.mx && dns.mx.length > 0)
        }
      }
    };
  }

  private transformSslData(ssl: any): SslAnalysis {
    if (!ssl) {
      return {
        status: 'no_certificate',
        data: null,
        error: 'No SSL certificate found'
      };
    }

    return {
      status: 'success',
      data: {
        certificate: {
          subject: ssl.subject || '',
          issuer: ssl.issuer || '',
          validFrom: ssl.validFrom || '',
          validTo: ssl.validTo || '',
          serialNumber: ssl.serialNumber || '',
          fingerprint: ssl.fingerprint || '',
          signatureAlgorithm: ssl.signatureAlgorithm
        },
        validation: {
          isValid: ssl.isValid !== false,
          daysUntilExpiry: ssl.daysUntilExpiry || 0,
          isExpired: ssl.daysUntilExpiry ? ssl.daysUntilExpiry <= 0 : false,
          isSelfSigned: ssl.issuer?.includes('self-signed') || false
        },
        security: {
          keySize: ssl.keySize,
          protocol: ssl.protocol,
          vulnerabilities: []
        }
      }
    };
  }

  private transformNetworkData(network: any): NetworkAnalysis {
    if (!network) {
      return {
        status: 'skipped',
        data: null,
        error: 'Network scan was skipped'
      };
    }

    const openPorts = network.openPorts || [];
    const services = (network.services || []).map((service: any) => ({
      port: service.port,
      protocol: service.protocol,
      service: service.service,
      version: service.version,
      confidence: service.confidence || 'medium'
    }));

    return {
      status: 'success',
      data: {
        ports: {
          open: openPorts,
          filtered: [],
          total: openPorts.length
        },
        services,
        summary: {
          totalOpenPorts: openPorts.length,
          commonServices: services.filter((s: any) => 
            ['http', 'https', 'ssh', 'ftp', 'smtp'].includes(s.service.toLowerCase())
          ).map((s: any) => s.service),
          unusualPorts: openPorts.filter((port: number) => 
            ![21, 22, 25, 53, 80, 443, 993, 995].includes(port)
          )
        }
      }
    };
  }

  private transformSubdomainData(subdomains: any): SubdomainAnalysis {
    if (!subdomains) {
      return {
        status: 'skipped',
        data: null,
        error: 'Subdomain discovery was not enabled'
      };
    }

    const statistics = {
      total: subdomains.totalFound || 0,
      bySource: {
        'Certificate Transparency': subdomains.sources?.certificateTransparency?.length || 0,
        'Common Names': subdomains.sources?.commonNames?.length || 0
      },
      patterns: this.analyzeSubdomainPatterns(subdomains.subdomains || []),
      depthAnalysis: this.analyzeSubdomainDepth(subdomains.subdomains || [])
    };

    return {
      status: 'success',
      data: {
        subdomains: subdomains.subdomains || [],
        sources: {
          certificateTransparency: subdomains.sources?.certificateTransparency || [],
          commonNames: subdomains.sources?.commonNames || []
        },
        statistics
      }
    };
  }

  private analyzeSubdomainPatterns(subdomains: string[]): { [pattern: string]: number } {
    const patterns: { [pattern: string]: number } = {};
    
    subdomains.forEach(subdomain => {
      const parts = subdomain.split('.');
      if (parts.length >= 3) {
        const firstLevel = parts[parts.length - 3];
        patterns[firstLevel] = (patterns[firstLevel] || 0) + 1;
      }
    });

    return patterns;
  }

  private analyzeSubdomainDepth(subdomains: string[]): { [depth: number]: number } {
    const depths: { [depth: number]: number } = {};
    
    subdomains.forEach(subdomain => {
      const parts = subdomain.split('.');
      const depth = parts.length - 2; // Subtract base domain parts
      depths[depth] = (depths[depth] || 0) + 1;
    });

    return depths;
  }

  private performThreatAssessment(domainInfo: DomainInfo): ThreatAssessment {
    const threats: ThreatIndicator[] = [];
    let riskScore = 0;

    // SSL Certificate Analysis
    if (!domainInfo.ssl) {
      threats.push({
        type: 'missing_ssl',
        severity: 'high',
        title: 'No SSL Certificate',
        description: 'Domain does not have an SSL certificate configured',
        recommendation: 'Install and configure an SSL certificate to encrypt communications'
      });
      riskScore += 25;
    } else if (domainInfo.ssl.daysUntilExpiry !== undefined && domainInfo.ssl.daysUntilExpiry < 30) {
      const severity = domainInfo.ssl.daysUntilExpiry < 7 ? 'critical' : 'high';
      threats.push({
        type: 'ssl_expiry',
        severity,
        title: 'SSL Certificate Expiring Soon',
        description: `SSL certificate expires in ${domainInfo.ssl.daysUntilExpiry} days`,
        recommendation: 'Renew SSL certificate before expiration to avoid service disruption',
        evidence: { daysUntilExpiry: domainInfo.ssl.daysUntilExpiry }
      });
      riskScore += severity === 'critical' ? 30 : 20;
    }

    // Domain Age Analysis
    if (domainInfo.whois?.registrationDate) {
      const regDate = new Date(domainInfo.whois.registrationDate);
      const daysSinceReg = (Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24);
      
      if (daysSinceReg < 30) {
        threats.push({
          type: 'recent_registration',
          severity: 'medium',
          title: 'Recently Registered Domain',
          description: `Domain was registered ${Math.round(daysSinceReg)} days ago`,
          recommendation: 'Verify domain legitimacy if unexpected',
          evidence: { daysSinceRegistration: Math.round(daysSinceReg) }
        });
        riskScore += 15;
      }
    }

    // Network Exposure Analysis
    const openPorts = domainInfo.network?.openPorts?.length || 0;
    if (openPorts > 5) {
      threats.push({
        type: 'open_ports',
        severity: 'medium',
        title: 'Multiple Open Ports',
        description: `${openPorts} open ports detected`,
        recommendation: 'Review and close unnecessary ports to reduce attack surface',
        evidence: { openPorts: domainInfo.network?.openPorts }
      });
      riskScore += 10;
    }

    // Determine overall risk level
    let overallRisk: 'low' | 'medium' | 'high' | 'critical';
    if (riskScore >= 70) overallRisk = 'critical';
    else if (riskScore >= 40) overallRisk = 'high';
    else if (riskScore >= 20) overallRisk = 'medium';
    else overallRisk = 'low';

    const summary = {
      criticalIssues: threats.filter(t => t.severity === 'critical').length,
      warnings: threats.filter(t => t.severity === 'high' || t.severity === 'medium').length,
      informational: threats.filter(t => t.severity === 'low' || t.severity === 'info').length
    };

    return {
      overallRisk,
      riskScore,
      threats,
      recommendations: threats.map(t => t.recommendation).filter(Boolean) as string[],
      summary
    };
  }

  private collectDataSources(domainInfo: DomainInfo): DataSources {
    return {
      whois: domainInfo.whois ? ['WHOIS Registry'] : [],
      dns: domainInfo.dns ? ['System DNS Resolver'] : [],
      ssl: domainInfo.ssl ? ['TLS Connection'] : [],
      network: domainInfo.network ? ['TCP Port Scan'] : [],
      subdomains: domainInfo.subdomains ? [
        ...(domainInfo.subdomains.sources.certificateTransparency.length > 0 ? ['Certificate Transparency (crt.sh)'] : []),
        ...(domainInfo.subdomains.sources.commonNames.length > 0 ? ['Common Name Enumeration'] : [])
      ] : [],
      threatIntelligence: ['Internal Analysis Engine']
    };
  }

  async exportToFile(filename: string): Promise<void> {
    const response = this.generateResponse();
    const jsonContent = JSON.stringify(response, null, 2);
    
    // Ensure the filename has .json extension
    const jsonFilename = filename.endsWith('.json') ? filename : `${filename}.json`;
    
    // Get absolute path
    const fullPath = path.resolve(jsonFilename);
    
    try {
      await fs.promises.writeFile(fullPath, jsonContent, 'utf8');
      console.log(`\nJSON written to ${fullPath} (${this.domains.length} domain(s), schema v${response.meta.version})`);
    } catch (error) {
      console.error(`Failed to write JSON: ${error}`);
      throw error;
    }
  }

  private generateResponse(): DomainAnalysisResponse {
    const meta: ResponseMetadata = {
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      requestId: this.requestId,
      executionTimeMs: Date.now() - this.startTime,
      totalDomains: this.domains.length,
      options: {
        includeSubdomains: !!this.options.subdomains,
        includeNetworkScan: !this.options.quick,
        quickScan: !!this.options.quick,
        verbose: !!this.options.verbose
      }
    };

    return {
      meta,
      data: this.domains
    };
  }

  getAnalysisCount(): number {
    return this.domains.length;
  }

  // Method to get the structured data for API use
  getStructuredData(): DomainAnalysisResponse {
    return this.generateResponse();
  }
}