#!/usr/bin/env node
// Packs the tarball exactly as it would be published, installs it into a throwaway
// directory (resolving real dependency versions like a user would), and runs the
// binary. This catches breakage that unit tests miss — e.g. an ESM/CJS interop
// change in a transitive dependency that only surfaces on a fresh install.
//
// Hermetic: only runs `--version` and `--help`, which still load every module
// (including the `whois` import), so a module-load crash fails the smoke.

import { execSync } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const run = (cmd, opts = {}) => execSync(cmd, { encoding: 'utf8', stdio: 'pipe', ...opts });

const COMMANDS = ['inspect', 'whois', 'dns', 'ssl', 'ports', 'subdomains', 'mcp'];

let tarball;
let dir;
try {
  console.log('• packing tarball...');
  const packed = JSON.parse(run('npm pack --json'));
  tarball = join(process.cwd(), packed[0].filename);

  dir = mkdtempSync(join(tmpdir(), 'domainlooker-smoke-'));
  console.log(`• installing ${packed[0].filename} into a clean dir...`);
  run('npm init -y', { cwd: dir });
  run(`npm install "${tarball}"`, { cwd: dir });

  const bin = join(dir, 'node_modules', '.bin', 'domainlooker');

  const version = run(`"${bin}" --version`, { cwd: dir }).trim();
  if (!/^\d+\.\d+\.\d+/.test(version)) throw new Error(`unexpected --version output: ${version}`);
  console.log(`• binary starts, --version -> ${version}`);

  const help = run(`"${bin}" --help`, { cwd: dir });
  const missing = COMMANDS.filter(c => !help.includes(c));
  if (missing.length) throw new Error(`--help is missing commands: ${missing.join(', ')}`);
  console.log(`• --help lists all ${COMMANDS.length} commands`);

  console.log('\n✓ package smoke test passed');
} catch (error) {
  console.error('\n✗ package smoke test FAILED');
  console.error(error.stderr || error.message || error);
  process.exitCode = 1;
} finally {
  if (dir) rmSync(dir, { recursive: true, force: true });
  if (tarball) rmSync(tarball, { force: true });
}
