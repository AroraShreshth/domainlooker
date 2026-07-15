import chalk from 'chalk';
import Table from 'cli-table3';
import { CSVExportService } from './services/csv-export.js';
import { JsonExportService } from './services/json-export.js';
import { DomainCollector, CollectOptions, hasWhoisData, hasDnsData, collectAdvisories } from './core/collector.js';
import { createSpinner, heading, domainHeading, printError } from './ui/effects.js';
import {
  DomainInfo,
  InspectionOptions,
  WhoisData,
  DNSData,
  SSLData,
  NetworkData,
  SubdomainData,
} from './types/index.js';

export class DomainInspector {
  private collector = new DomainCollector();
  private csvExporter?: CSVExportService;
  private jsonExporter?: JsonExportService;

  constructor(private options: InspectionOptions = {}) {
    if (this.options.exportCsv) {
      this.csvExporter = new CSVExportService();
    }
    if (this.options.exportJson) {
      this.jsonExporter = new JsonExportService(this.options);
    }
  }

  private collectOptions(): CollectOptions {
    return {
      quick: this.options.quick,
      subdomains: this.options.subdomains,
      onError: (_service, error) => this.logVerbose(error),
    };
  }

  // --- Full multi-aspect report ----------------------------------------------

  async inspect(domain: string): Promise<void> {
    const info = await this.withSpinner(`Inspecting ${domain}`, () => this.gather(domain));
    this.renderReport(info);

    if (this.csvExporter && this.options.exportCsv) {
      this.csvExporter.addDomain(info);
      await this.csvExporter.exportToFile(this.options.exportCsv);
    }
    if (this.jsonExporter && this.options.exportJson) {
      this.jsonExporter.addDomain(info);
      await this.jsonExporter.exportToFile(this.options.exportJson);
    }
  }

  async inspectMany(domains: string[], parallelLimit: number = 3): Promise<void> {
    console.log(chalk.bold(`\nInspecting ${domains.length} domains (${parallelLimit} in parallel)`));

    for (let i = 0; i < domains.length; i += parallelLimit) {
      const batch = domains.slice(i, i + parallelLimit);
      const settled = await this.withSpinner(
        `Inspecting ${batch.join(', ')}`,
        () => Promise.allSettled(batch.map(domain => this.gather(domain))),
      );

      for (let j = 0; j < settled.length; j++) {
        const outcome = settled[j];
        if (outcome.status === 'rejected') {
          // gather() is written never to reject; guard defensively so one bad
          // domain can never drop the rest of the batch.
          printError(`Failed to inspect ${batch[j]}: ${outcome.reason}`);
          continue;
        }
        const info = outcome.value;
        this.renderReport(info);
        this.csvExporter?.addDomain(info);
        this.jsonExporter?.addDomain(info);
      }
    }

    if (this.csvExporter && this.options.exportCsv) {
      await this.csvExporter.exportToFile(this.options.exportCsv);
    }
    if (this.jsonExporter && this.options.exportJson) {
      await this.jsonExporter.exportToFile(this.options.exportJson);
    }
  }

  private renderReport(info: DomainInfo): void {
    domainHeading(info.domain);
    if (hasWhoisData(info.whois)) this.renderWhois(info.whois);
    if (hasDnsData(info.dns)) this.renderDns(info.dns);
    if (info.ssl) this.renderSsl(info.ssl);
    if (info.network?.openPorts?.length) this.renderPorts(info.network);
    if (info.subdomains && info.subdomains.totalFound > 0) this.renderSubdomains(info.subdomains);
    this.renderAdvisories(info);
  }

  // --- Single-aspect commands ------------------------------------------------
  //
  // Each runs one lookup under a single spinner (only one `ora` is ever live)
  // and returns true when data was found and rendered, false otherwise.

  async whoisReport(domain: string): Promise<boolean> {
    const data = await this.withSpinner(`WHOIS ${domain}`, () => this.collector.whois(domain, this.collectOptions()));
    if (hasWhoisData(data)) { this.renderWhois(data); return true; }
    console.log('No WHOIS data available.');
    return false;
  }

  async dnsReport(domain: string): Promise<boolean> {
    const data = await this.withSpinner(`DNS ${domain}`, () => this.collector.dns(domain, this.collectOptions()));
    if (hasDnsData(data)) { this.renderDns(data); return true; }
    console.log('No DNS records found.');
    return false;
  }

  async sslReport(domain: string): Promise<boolean> {
    const data = await this.withSpinner(`SSL ${domain}`, () => this.collector.ssl(domain, this.collectOptions()));
    if (data) { this.renderSsl(data); return true; }
    console.log('No SSL certificate found.');
    return false;
  }

  async portsReport(domain: string): Promise<boolean> {
    const data = await this.withSpinner(`Ports ${domain}`, () => this.collector.ports(domain, this.collectOptions()));
    if (data?.openPorts?.length) { this.renderPorts(data); return true; }
    console.log('No open ports detected.');
    return false;
  }

  async subdomainReport(domain: string): Promise<boolean> {
    const data = await this.withSpinner(`Subdomains ${domain}`, () => this.collector.subdomains(domain, this.collectOptions()));
    if (data && data.totalFound > 0) { this.renderSubdomains(data); return true; }
    console.log('No subdomains found.');
    return false;
  }

  // --- Data gathering --------------------------------------------------------

  private gather(domain: string): Promise<DomainInfo> {
    return this.collector.collect(domain, this.collectOptions());
  }

  /** Run `work` under a single spinner so concurrent lookups never fight for the TTY line. */
  private async withSpinner<T>(label: string, work: () => Promise<T>): Promise<T> {
    const spinner = createSpinner(label).start();
    try {
      const result = await work();
      spinner.succeed(label);
      return result;
    } catch (error) {
      spinner.fail(label);
      throw error;
    }
  }

  private logVerbose(error: unknown): void {
    if (this.options.verbose) {
      printError(String(error));
    }
  }

  // --- Section renderers -----------------------------------------------------

  private renderWhois(whois: WhoisData): void {
    heading('Registration (WHOIS)');
    const table = new Table({ colWidths: [20, 50], wordWrap: true });
    if (whois.registrar) table.push(['Registrar', whois.registrar]);
    if (whois.registrationDate) table.push(['Registered', whois.registrationDate]);
    if (whois.expirationDate) table.push(['Expires', whois.expirationDate]);
    if (whois.registrantCountry) table.push(['Country', whois.registrantCountry]);
    if (whois.nameServers?.length) table.push(['Name servers', whois.nameServers.join('\n')]);
    if (whois.status?.length) table.push(['Status', whois.status.join('\n')]);
    console.log(table.toString());
  }

  private renderDns(dns: DNSData): void {
    heading('DNS records');
    const table = new Table({ colWidths: [15, 55], wordWrap: true });
    if (dns.a?.length) table.push(['A', dns.a.join('\n')]);
    if (dns.aaaa?.length) table.push(['AAAA', dns.aaaa.join('\n')]);
    // A "null MX" (RFC 7505) has an empty exchange — skip it rather than print a bare priority.
    const mx = dns.mx?.filter(m => m.exchange && m.exchange !== '.') ?? [];
    if (mx.length) table.push(['MX', mx.map(m => `${m.priority} ${m.exchange}`).join('\n')]);
    if (dns.ns?.length) table.push(['NS', dns.ns.join('\n')]);
    if (dns.txt?.length) table.push(['TXT', dns.txt.slice(0, 5).join('\n')]);
    if (dns.soa) table.push(['SOA', `${dns.soa.primary} (serial ${dns.soa.serial})`]);
    console.log(table.toString());
  }

  private renderSsl(ssl: SSLData): void {
    heading('SSL certificate');
    const table = new Table({ colWidths: [20, 50], wordWrap: true });
    if (ssl.subject) table.push(['Subject', ssl.subject]);
    if (ssl.issuer) table.push(['Issuer', ssl.issuer]);
    if (ssl.validFrom) table.push(['Valid from', ssl.validFrom]);
    if (ssl.validTo) table.push(['Valid to', ssl.validTo]);
    if (ssl.daysUntilExpiry !== undefined) {
      const days = ssl.daysUntilExpiry;
      const color = days < 30 ? chalk.red : days < 90 ? chalk.yellow : chalk.green;
      table.push(['Days until expiry', color(`${days}`)]);
    }
    if (ssl.signatureAlgorithm) table.push(['Signature', ssl.signatureAlgorithm]);
    if (ssl.fingerprint) table.push(['Fingerprint', ssl.fingerprint]);
    console.log(table.toString());
  }

  private renderPorts(network: NetworkData): void {
    if (!network.openPorts?.length) return;
    heading('Open ports');
    const table = new Table({ head: ['Port', 'Protocol', 'Service'], colWidths: [10, 12, 18] });
    network.services?.forEach(service => {
      table.push([service.port.toString(), service.protocol, service.service]);
    });
    console.log(table.toString());
  }

  private renderSubdomains(sub: SubdomainData): void {
    heading(`Subdomains (${sub.totalFound} found)`);

    const summary = new Table({ colWidths: [28, 12] });
    summary.push(
      ['Certificate transparency', sub.sources.certificateTransparency.length.toString()],
      ['Common names', sub.sources.commonNames.length.toString()],
    );
    console.log(summary.toString());

    if (sub.subdomains.length === 0) return;

    const limit = Math.min(20, sub.subdomains.length);
    const list = new Table({ head: ['Subdomain', 'Source'], colWidths: [45, 24], wordWrap: true });
    for (let i = 0; i < limit; i++) {
      const name = sub.subdomains[i];
      const found: string[] = [];
      if (sub.sources.certificateTransparency.includes(name)) found.push('Cert transparency');
      if (sub.sources.commonNames.includes(name)) found.push('Common name');
      list.push([name, found.join(', ') || 'Unknown']);
    }
    console.log(list.toString());

    if (sub.subdomains.length > limit) {
      console.log(chalk.dim(`... and ${sub.subdomains.length - limit} more`));
    }
  }

  private renderAdvisories(info: DomainInfo): void {
    heading('Advisories');
    const advisories = collectAdvisories(info);
    if (advisories.length === 0) {
      console.log(chalk.green('No issues found.'));
      return;
    }
    for (const advisory of advisories) {
      console.log(chalk.yellow(`- ${advisory}`));
    }
  }
}
