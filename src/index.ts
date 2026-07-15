#!/usr/bin/env node

import { Command } from 'commander';
import { DomainInspector } from './domain-inspector.js';
import { startStdioServer } from './mcp/server.js';
import { isDomainShaped } from './core/target-guard.js';
import { printError } from './ui/effects.js';
import { VERSION } from './version.js';

const program = new Command();

program
  .name('domainlooker')
  .description('A fast CLI + MCP server for inspecting domains: WHOIS, DNS, SSL, ports, and subdomains.')
  .version(VERSION)
  .showHelpAfterError('(run with --help for a list of commands)');

program
  .command('inspect', { isDefault: true })
  .description('Run a full report (WHOIS, DNS, SSL, ports, advisories)')
  .argument('<domains...>', 'One or more domains to inspect')
  .option('-v, --verbose', 'Show underlying errors')
  .option('-q, --quick', 'Skip the port scan')
  .option('--subdomains', 'Also discover subdomains')
  .option('-p, --parallel <number>', 'Domains to process in parallel', '3')
  .option('--export-csv <file>', 'Write results to a CSV file')
  .option('--export-json <file>', 'Write results to a JSON file')
  .action(async (domains: string[], options) => {
    const invalid = domains.filter(d => !isDomainShaped(d));
    if (invalid.length > 0) {
      printError(`not a valid domain: ${invalid.map(d => `'${d}'`).join(', ')}`);
      console.error("(run 'domainlooker --help' to see available commands)");
      process.exitCode = 1;
      return;
    }

    const inspector = new DomainInspector(options);
    if (domains.length === 1) {
      await inspector.inspect(domains[0]);
    } else {
      await inspector.inspectMany(domains, parseInt(options.parallel, 10));
    }
  });

interface SingleAspectCommand {
  name: string;
  description: string;
  run: (inspector: DomainInspector, domain: string) => Promise<boolean>;
}

const singleAspectCommands: SingleAspectCommand[] = [
  { name: 'whois', description: 'Show registration (WHOIS) data', run: (i, d) => i.whoisReport(d) },
  { name: 'dns', description: 'Show DNS records', run: (i, d) => i.dnsReport(d) },
  { name: 'ssl', description: 'Show the SSL certificate', run: (i, d) => i.sslReport(d) },
  { name: 'ports', description: 'Scan for open ports', run: (i, d) => i.portsReport(d) },
  { name: 'subdomains', description: 'Discover subdomains', run: (i, d) => i.subdomainReport(d) },
];

for (const { name, description, run } of singleAspectCommands) {
  program
    .command(name)
    .description(description)
    .argument('<domain>', 'Domain to inspect')
    .option('-v, --verbose', 'Show underlying errors')
    .action(async (domain: string, options) => {
      const inspector = new DomainInspector(options);
      const found = await run(inspector, domain);
      // Exit non-zero when nothing was found, so scripts can branch on it.
      if (!found) process.exitCode = 1;
    });
}

program
  .command('mcp')
  .description('Run as an MCP server over stdio (for AI agents/clients)')
  .action(async () => {
    // stdout is reserved for the MCP protocol, so the process stays otherwise silent.
    await startStdioServer();
  });

async function main(): Promise<void> {
  try {
    await program.parseAsync(process.argv);
  } catch (error) {
    printError(String(error));
    process.exitCode = 1;
  }
}

main();
