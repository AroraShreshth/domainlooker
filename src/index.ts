#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import figlet from 'figlet';
import gradient from 'gradient-string';
import boxen from 'boxen';
import { DomainInspector } from './domain-inspector';
import { displayBanner, typeWriter } from './ui/effects';

const program = new Command();

async function main() {
  await displayBanner();
  
  program
    .name('domainlooker')
    .description('🕵️  Mission-critical domain intelligence gathering tool')
    .version('0.1.1');

  program
    .argument('<domains...>', 'Target domain(s) to investigate (space-separated for multiple)')
    .option('-v, --verbose', 'Enable verbose output')
    .option('-q, --quick', 'Quick scan only')
    .option('--no-banner', 'Skip the banner')
    .option('-p, --parallel <number>', 'Number of domains to process in parallel (default: 3)', '3')
    .option('--export-csv <filename>', 'Export results to CSV file')
    .option('--export-json <filename>', 'Export results to structured JSON file')
    .option('--subdomains', 'Enable subdomain discovery and enumeration')
    .action(async (domains: string[], options) => {
      const inspector = new DomainInspector(options);
      
      if (domains.length === 1) {
        // Single domain analysis
        await inspector.investigate(domains[0]);
      } else {
        // Multiple domain analysis
        await inspector.investigateMultiple(domains, parseInt(options.parallel));
      }
    });

  program.parse();
}

if (require.main === module) {
  main().catch(console.error);
}