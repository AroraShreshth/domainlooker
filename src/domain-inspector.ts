import chalk from 'chalk';
import Table from 'cli-table3';
import { WhoisService } from './services/whois';
import { DNSService } from './services/dns';
import { SSLService } from './services/ssl';
import { NetworkService } from './services/network';
import { SubdomainService } from './services/subdomain';
import { CSVExportService } from './services/csv-export';
import { JsonExportService } from './services/json-export';
import { createSpinner, missionComplete, criticalAlert } from './ui/effects';
import { DomainInfo, InspectionOptions } from './types';

export class DomainInspector {
  private whoisService = new WhoisService();
  private dnsService = new DNSService();
  private sslService = new SSLService();
  private networkService = new NetworkService();
  private subdomainService = new SubdomainService();
  private csvExporter?: CSVExportService;
  private jsonExporter?: JsonExportService;

  constructor(private options: InspectionOptions = {}) {
    // Initialize CSV exporter if export option is provided
    if (this.options.exportCsv) {
      this.csvExporter = new CSVExportService();
    }
    
    // Initialize JSON exporter if export option is provided
    if (this.options.exportJson) {
      this.jsonExporter = new JsonExportService(this.options);
    }
  }

  async investigateMultiple(domains: string[], parallelLimit: number = 3): Promise<void> {
    console.log(chalk.magenta.bold('\n' + '█'.repeat(80)));
    console.log(chalk.magenta.bold(`🎯 MULTIPLE TARGETS ACQUIRED: ${domains.length} DOMAINS`));
    console.log(chalk.magenta.bold(`📡 Processing ${parallelLimit} domains in parallel`));
    console.log(chalk.magenta.bold('█'.repeat(80)));

    // Process domains in batches
    for (let i = 0; i < domains.length; i += parallelLimit) {
      const batch = domains.slice(i, i + parallelLimit);
      const batchNum = Math.floor(i / parallelLimit) + 1;
      const totalBatches = Math.ceil(domains.length / parallelLimit);
      
      console.log(chalk.cyan.bold(`\n🔄 BATCH ${batchNum}/${totalBatches}: ${batch.join(' • ')}`));
      
      // Process current batch in parallel
      const batchPromises = batch.map(domain => this.investigateSingle(domain));
      await Promise.allSettled(batchPromises);
      
      // Add separator between batches (except for last batch)
      if (i + parallelLimit < domains.length) {
        console.log('\n' + chalk.magenta('█'.repeat(80)));
        console.log(chalk.yellow.bold('⏳ PREPARING NEXT BATCH...'));
        console.log(chalk.magenta('█'.repeat(80)));
        await new Promise(resolve => setTimeout(resolve, 1500)); // Brief pause between batches
      }
    }

    // Final completion summary
    console.log('\n' + chalk.green.bold('█'.repeat(80)));
    console.log(chalk.green.bold(`🎉 MISSION COMPLETE: ALL ${domains.length} DOMAINS ANALYZED`));
    console.log(chalk.green.bold('█'.repeat(80)));

    // Export to CSV if requested
    if (this.csvExporter && this.options.exportCsv) {
      await this.csvExporter.exportToFile(this.options.exportCsv);
    }
    
    // Export to JSON if requested
    if (this.jsonExporter && this.options.exportJson) {
      await this.jsonExporter.exportToFile(this.options.exportJson);
    }
  }

  private async investigateSingle(domain: string): Promise<void> {
    try {
      // Clear separation with domain header
      console.log('\n' + chalk.yellow('='.repeat(80)));
      console.log(chalk.yellow.bold(`🎯 ANALYZING TARGET: ${domain.toUpperCase()}`));
      console.log(chalk.yellow('='.repeat(80)));
      console.log(chalk.cyan('📡 Initiating intelligence gathering operations...\n'));
      
      const domainInfo: DomainInfo = { domain };

      // Execute intelligence gathering (same parallel logic as original)
      const whoisSpinner = createSpinner(`WHOIS: ${domain}`);
      const dnsSpinner = createSpinner(`DNS: ${domain}`);
      const sslSpinner = createSpinner(`SSL: ${domain}`);
      const networkSpinner = this.options.quick ? null : createSpinner(`Network: ${domain}`);
      const subdomainSpinner = this.options.subdomains ? createSpinner(`Subdomains: ${domain}`) : null;

      whoisSpinner.start();
      dnsSpinner.start();
      sslSpinner.start();
      if (networkSpinner) networkSpinner.start();
      if (subdomainSpinner) subdomainSpinner.start();

      const intelligencePromises = [
        this.gatherWhoisIntelligence(domain, whoisSpinner),
        this.gatherDnsIntelligence(domain, dnsSpinner),
        this.gatherSslIntelligence(domain, sslSpinner),
        ...(this.options.quick ? [] : [this.gatherNetworkIntelligence(domain, networkSpinner!)]),
        ...(this.options.subdomains ? [this.gatherSubdomainIntelligence(domain, subdomainSpinner!)] : [])
      ];

      const results = await Promise.allSettled(intelligencePromises);

      // Process results more carefully for multiple domain scenario
      let resultIndex = 0;
      domainInfo.whois = results[resultIndex].status === 'fulfilled' ? (results[resultIndex] as PromiseFulfilledResult<any>).value : null;
      resultIndex++;
      
      domainInfo.dns = results[resultIndex].status === 'fulfilled' ? (results[resultIndex] as PromiseFulfilledResult<any>).value : null;
      resultIndex++;
      
      domainInfo.ssl = results[resultIndex].status === 'fulfilled' ? (results[resultIndex] as PromiseFulfilledResult<any>).value : null;
      resultIndex++;
      
      if (!this.options.quick) {
        domainInfo.network = results[resultIndex].status === 'fulfilled' ? (results[resultIndex] as PromiseFulfilledResult<any>).value : null;
        resultIndex++;
      }
      
      if (this.options.subdomains) {
        domainInfo.subdomains = results[resultIndex].status === 'fulfilled' ? (results[resultIndex] as PromiseFulfilledResult<any>).value : null;
      }

      // Use full detailed report for each domain
      await this.generateIntelligenceReport(domainInfo);

      // Add to CSV export if enabled
      if (this.csvExporter) {
        this.csvExporter.addDomain(domainInfo);
      }
      
      // Add to JSON export if enabled
      if (this.jsonExporter) {
        this.jsonExporter.addDomain(domainInfo);
      }

    } catch (error) {
      console.log(chalk.red(`❌ Failed to analyze ${domain}: ${error}`));
    }
  }

  async investigate(domain: string): Promise<void> {
    console.log(chalk.yellow(`🎯 TARGET ACQUIRED: ${domain.toUpperCase()}`));
    console.log(chalk.cyan('📡 Initiating intelligence gathering operations...\n'));

    const domainInfo: DomainInfo = { domain };

    try {
      // Initialize all spinners
      const whoisSpinner = createSpinner('Accessing WHOIS intelligence database...');
      const dnsSpinner = createSpinner('Intercepting DNS communications...');
      const sslSpinner = createSpinner('Analyzing encryption protocols...');
      const networkSpinner = this.options.quick ? null : createSpinner('Conducting network reconnaissance...');
      const subdomainSpinner = this.options.subdomains ? createSpinner('Discovering subdomains...') : null;

      // Start all spinners
      whoisSpinner.start();
      dnsSpinner.start();
      sslSpinner.start();
      if (networkSpinner) networkSpinner.start();
      if (subdomainSpinner) subdomainSpinner.start();

      // Execute all intelligence gathering operations in parallel
      const intelligencePromises = [
        this.gatherWhoisIntelligence(domain, whoisSpinner),
        this.gatherDnsIntelligence(domain, dnsSpinner),
        this.gatherSslIntelligence(domain, sslSpinner),
        ...(this.options.quick ? [] : [this.gatherNetworkIntelligence(domain, networkSpinner!)]),
        ...(this.options.subdomains ? [this.gatherSubdomainIntelligence(domain, subdomainSpinner!)] : [])
      ];

      const results = await Promise.allSettled(intelligencePromises);

      // Process results more carefully for single domain scenario
      let resultIndex = 0;
      domainInfo.whois = results[resultIndex].status === 'fulfilled' ? (results[resultIndex] as PromiseFulfilledResult<any>).value : null;
      resultIndex++;
      
      domainInfo.dns = results[resultIndex].status === 'fulfilled' ? (results[resultIndex] as PromiseFulfilledResult<any>).value : null;
      resultIndex++;
      
      domainInfo.ssl = results[resultIndex].status === 'fulfilled' ? (results[resultIndex] as PromiseFulfilledResult<any>).value : null;
      resultIndex++;
      
      if (!this.options.quick) {
        domainInfo.network = results[resultIndex].status === 'fulfilled' ? (results[resultIndex] as PromiseFulfilledResult<any>).value : null;
        resultIndex++;
      }
      
      if (this.options.subdomains) {
        domainInfo.subdomains = results[resultIndex].status === 'fulfilled' ? (results[resultIndex] as PromiseFulfilledResult<any>).value : null;
      }

      await this.generateIntelligenceReport(domainInfo);

      // Add to CSV export if enabled
      if (this.csvExporter) {
        this.csvExporter.addDomain(domainInfo);
        await this.csvExporter.exportToFile(this.options.exportCsv!);
      }
      
      // Add to JSON export if enabled
      if (this.jsonExporter) {
        this.jsonExporter.addDomain(domainInfo);
        await this.jsonExporter.exportToFile(this.options.exportJson!);
      }

    } catch (error) {
      criticalAlert(`Mission failed: ${error}`);
    }
  }

  private async generateIntelligenceReport(info: DomainInfo): Promise<void> {
    console.log('\n' + chalk.yellow('=' .repeat(60)));
    console.log(chalk.yellow.bold(`🔍 INTELLIGENCE REPORT: ${info.domain.toUpperCase()}`));
    console.log(chalk.yellow('=' .repeat(60)) + '\n');

    // WHOIS Intelligence
    if (info.whois) {
      console.log(chalk.cyan.bold('📋 REGISTRATION INTELLIGENCE'));
      const whoisTable = new Table({
        style: { head: ['cyan'] },
        colWidths: [20, 40]
      });

      if (info.whois.registrar) whoisTable.push(['Registrar', info.whois.registrar]);
      if (info.whois.registrationDate) whoisTable.push(['Registered', info.whois.registrationDate]);
      if (info.whois.expirationDate) whoisTable.push(['Expires', info.whois.expirationDate]);
      if (info.whois.registrantCountry) whoisTable.push(['Country', info.whois.registrantCountry]);
      if (info.whois.status) whoisTable.push(['Status', info.whois.status.join(', ')]);

      console.log(whoisTable.toString());
      console.log();
    }

    // DNS Intelligence
    if (info.dns) {
      console.log(chalk.green.bold('🌐 DNS INTELLIGENCE'));
      const dnsTable = new Table({
        style: { head: ['green'] },
        colWidths: [15, 45]
      });

      if (info.dns.a && info.dns.a.length > 0) {
        dnsTable.push(['A Records', info.dns.a.join('\n')]);
      }
      if (info.dns.aaaa && info.dns.aaaa.length > 0) {
        dnsTable.push(['AAAA Records', info.dns.aaaa.join('\n')]);
      }
      if (info.dns.mx && info.dns.mx.length > 0) {
        const mxRecords = info.dns.mx.map(mx => `${mx.priority} ${mx.exchange}`).join('\n');
        dnsTable.push(['MX Records', mxRecords]);
      }
      if (info.dns.ns && info.dns.ns.length > 0) {
        dnsTable.push(['NS Records', info.dns.ns.join('\n')]);
      }
      if (info.dns.txt && info.dns.txt.length > 0) {
        dnsTable.push(['TXT Records', info.dns.txt.slice(0, 3).join('\n')]);
      }

      console.log(dnsTable.toString());
      console.log();
    }

    // SSL Certificate Intelligence
    if (info.ssl) {
      console.log(chalk.magenta.bold('🔒 ENCRYPTION INTELLIGENCE'));
      const sslTable = new Table({
        style: { head: ['magenta'] },
        colWidths: [20, 40]
      });

      if (info.ssl.subject) sslTable.push(['Subject', info.ssl.subject]);
      if (info.ssl.issuer) sslTable.push(['Issuer', info.ssl.issuer]);
      if (info.ssl.validFrom) sslTable.push(['Valid From', info.ssl.validFrom]);
      if (info.ssl.validTo) sslTable.push(['Valid To', info.ssl.validTo]);
      if (info.ssl.daysUntilExpiry !== undefined) {
        const expiryColor = info.ssl.daysUntilExpiry < 30 ? 'red' : 
                           info.ssl.daysUntilExpiry < 90 ? 'yellow' : 'green';
        sslTable.push(['Days Until Expiry', chalk[expiryColor](`${info.ssl.daysUntilExpiry} days`)]);
      }
      if (info.ssl.fingerprint) sslTable.push(['Fingerprint', info.ssl.fingerprint]);
      if (info.ssl.signatureAlgorithm) sslTable.push(['Signature Algorithm', info.ssl.signatureAlgorithm]);

      console.log(sslTable.toString());
      console.log();
    }

    // Network Intelligence
    if (info.network && info.network.openPorts && info.network.openPorts.length > 0) {
      console.log(chalk.blue.bold('🌐 NETWORK INTELLIGENCE'));
      const networkTable = new Table({
        style: { head: ['blue'] },
        head: ['Port', 'Protocol', 'Service', 'Status'],
        colWidths: [8, 12, 15, 10]
      });

      info.network.services?.forEach(service => {
        networkTable.push([
          service.port.toString(),
          service.protocol,
          service.service,
          chalk.red('OPEN')
        ]);
      });

      console.log(networkTable.toString());
      console.log();
    }

    // Subdomain Intelligence
    if (info.subdomains && info.subdomains.totalFound > 0) {
      console.log(chalk.magenta.bold('🔍 SUBDOMAIN INTELLIGENCE'));
      
      // Summary table
      const subdomainSummary = new Table({
        style: { head: ['magenta'] },
        colWidths: [25, 35]
      });

      subdomainSummary.push(
        ['Total Subdomains Found', info.subdomains.totalFound.toString()],
        ['Certificate Transparency', info.subdomains.sources.certificateTransparency.length.toString()],
        ['Common Names Found', info.subdomains.sources.commonNames.length.toString()],
        ['DNS Enumeration', info.subdomains.sources.dnsEnumeration.length.toString()]
      );

      console.log(subdomainSummary.toString());

      // Display found subdomains (limit to first 20 for readability)
      if (info.subdomains.subdomains.length > 0) {
        console.log(chalk.magenta.bold('\n📋 DISCOVERED SUBDOMAINS'));
        const subdomainList = new Table({
          style: { head: ['magenta'] },
          head: ['Subdomain', 'Source'],
          colWidths: [40, 20]
        });

        const displayLimit = Math.min(20, info.subdomains.subdomains.length);
        
        for (let i = 0; i < displayLimit; i++) {
          const subdomain = info.subdomains.subdomains[i];
          let source = 'Unknown';
          
          if (info.subdomains.sources.certificateTransparency.includes(subdomain)) {
            source = 'Cert Transparency';
          } else if (info.subdomains.sources.commonNames.includes(subdomain)) {
            source = 'Common Name';
          } else if (info.subdomains.sources.dnsEnumeration.includes(subdomain)) {
            source = 'DNS Enum';
          }

          subdomainList.push([subdomain, source]);
        }

        console.log(subdomainList.toString());

        if (info.subdomains.subdomains.length > 20) {
          console.log(chalk.yellow(`... and ${info.subdomains.subdomains.length - 20} more subdomains`));
        }
      }

      console.log();
    }

    // Threat Assessment
    this.displayThreatAssessment(info);

    missionComplete(`Intelligence gathering complete for ${info.domain}`);
  }

  private async generateCompactReport(info: DomainInfo): Promise<void> {
    console.log(chalk.cyan(`\n📊 INTELLIGENCE SUMMARY: ${info.domain.toUpperCase()}`));
    
    const summary = new Table({
      style: { head: ['cyan'] },
      colWidths: [25, 35]
    });

    // Quick status overview
    const whoisStatus = info.whois ? '✅ Available' : '❌ Unavailable';
    const dnsStatus = info.dns && (info.dns.a || info.dns.aaaa) ? '✅ Resolved' : '❌ Failed';
    const sslStatus = info.ssl ? `✅ Valid (${info.ssl.daysUntilExpiry}d)` : '❌ No Certificate';
    const networkStatus = info.network?.openPorts?.length ? 
      `✅ ${info.network.openPorts.length} ports open` : '❌ No ports detected';

    summary.push(
      ['WHOIS Intelligence', whoisStatus],
      ['DNS Resolution', dnsStatus],
      ['SSL Certificate', sslStatus],
      ['Network Services', networkStatus]
    );

    // Key details
    if (info.whois?.registrar) {
      summary.push(['Registrar', info.whois.registrar]);
    }
    if (info.whois?.expirationDate) {
      summary.push(['Expires', info.whois.expirationDate]);
    }
    if (info.dns?.a && info.dns.a.length > 0) {
      summary.push(['IPv4 Address', info.dns.a[0]]);
    }
    if (info.ssl?.issuer) {
      summary.push(['SSL Issuer', info.ssl.issuer.split(',')[0]]);
    }

    console.log(summary.toString());

    // Quick threat assessment
    const threats = [];
    if (info.ssl?.daysUntilExpiry !== undefined && info.ssl.daysUntilExpiry < 30) {
      threats.push('⚠️  SSL expires soon');
    }
    if (!info.ssl) {
      threats.push('⚠️  No SSL certificate');
    }
    if (info.whois?.registrationDate) {
      const regDate = new Date(info.whois.registrationDate);
      const daysSinceReg = (Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24);
      if (daysSinceReg < 30) {
        threats.push('⚠️  Recently registered');
      }
    }

    if (threats.length > 0) {
      console.log(chalk.red('\n🚨 ALERTS: ' + threats.join(' | ')));
    } else {
      console.log(chalk.green('\n✅ No immediate threats detected'));
    }
  }

  private async gatherWhoisIntelligence(domain: string, spinner: any): Promise<any> {
    try {
      const result = await this.whoisService.lookup(domain);
      spinner.succeed(chalk.green('WHOIS intelligence gathered'));
      return result;
    } catch (error) {
      spinner.fail(chalk.red('WHOIS intelligence unavailable'));
      if (this.options.verbose) {
        console.log(chalk.red(`Error: ${error}`));
      }
      return null;
    }
  }

  private async gatherDnsIntelligence(domain: string, spinner: any): Promise<any> {
    try {
      const result = await this.dnsService.lookup(domain);
      spinner.succeed(chalk.green('DNS intelligence captured'));
      return result;
    } catch (error) {
      spinner.fail(chalk.red('DNS intelligence compromised'));
      if (this.options.verbose) {
        console.log(chalk.red(`Error: ${error}`));
      }
      return null;
    }
  }

  private async gatherSslIntelligence(domain: string, spinner: any): Promise<any> {
    try {
      const result = await this.sslService.getCertificate(domain);
      spinner.succeed(chalk.green('Encryption analysis complete'));
      return result;
    } catch (error) {
      spinner.fail(chalk.red('Encryption analysis failed'));
      if (this.options.verbose) {
        console.log(chalk.red(`Error: ${error}`));
      }
      return null;
    }
  }

  private async gatherNetworkIntelligence(domain: string, spinner: any): Promise<any> {
    try {
      const result = await this.networkService.getNetworkInfo(domain);
      spinner.succeed(chalk.green('Network reconnaissance complete'));
      return result;
    } catch (error) {
      spinner.fail(chalk.red('Network reconnaissance failed'));
      if (this.options.verbose) {
        console.log(chalk.red(`Error: ${error}`));
      }
      return null;
    }
  }

  private async gatherSubdomainIntelligence(domain: string, spinner: any): Promise<any> {
    try {
      const result = await this.subdomainService.discoverSubdomains(domain);
      spinner.succeed(chalk.green(`Subdomain discovery complete (${result.totalFound} found)`));
      return result;
    } catch (error) {
      spinner.fail(chalk.red('Subdomain discovery failed'));
      if (this.options.verbose) {
        console.log(chalk.red(`Error: ${error}`));
      }
      return null;
    }
  }

  private displayThreatAssessment(info: DomainInfo): void {
    console.log(chalk.red.bold('⚠️  THREAT ASSESSMENT'));
    
    const threats = [];
    
    // Check SSL expiry
    if (info.ssl?.daysUntilExpiry !== undefined && info.ssl.daysUntilExpiry < 30) {
      threats.push('SSL certificate expires soon');
    }
    
    // Check if no SSL
    if (!info.ssl) {
      threats.push('No SSL certificate detected');
    }
    
    // Check domain age (if registration is recent)
    if (info.whois?.registrationDate) {
      const regDate = new Date(info.whois.registrationDate);
      const now = new Date();
      const daysSinceReg = (now.getTime() - regDate.getTime()) / (1000 * 60 * 60 * 24);
      
      if (daysSinceReg < 30) {
        threats.push('Domain registered very recently');
      }
    }

    const threatTable = new Table({
      style: { head: ['red'] },
      colWidths: [60]
    });

    if (threats.length === 0) {
      threatTable.push([chalk.green('✅ No immediate threats detected')]);
    } else {
      threats.forEach(threat => {
        threatTable.push([chalk.red(`⚠️ ${threat}`)]);
      });
    }

    console.log(threatTable.toString());
    console.log();
  }
}