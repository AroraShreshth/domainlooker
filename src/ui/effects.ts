import chalk from 'chalk';
import ora, { Ora } from 'ora';

/** Print a section heading for a block of output. */
export function heading(text: string): void {
  console.log('\n' + chalk.bold.cyan(text));
  console.log(chalk.dim('─'.repeat(text.length)));
}

/** Print a heading for a single domain report. */
export function domainHeading(domain: string): void {
  const label = `Report: ${domain}`;
  console.log('\n' + chalk.bold(label));
  console.log(chalk.dim('═'.repeat(label.length)));
}

export function createSpinner(text: string): Ora {
  return ora({ text, spinner: 'dots' });
}

export function printError(message: string): void {
  console.error(chalk.red(`error: ${message}`));
}
