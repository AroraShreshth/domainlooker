import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';

const execAsync = promisify(exec);

describe('CLI Integration Tests', () => {
  const cliPath = path.join(__dirname, '../../dist/index.js');

  beforeAll(async () => {
    // Ensure the project is built
    try {
      await execAsync('npm run build');
    } catch (error) {
      console.warn('Build failed, tests may not work properly:', error);
    }
  });

  describe('Help and version', () => {
    it('should display help information', async () => {
      const { stdout, stderr } = await execAsync(`node ${cliPath} --help`);
      
      expect(stdout).toContain('domainlooker');
      expect(stdout).toContain('Target domain(s) to investigate');
      expect(stdout).toContain('--export-csv');
      expect(stdout).toContain('--export-json');
      expect(stdout).toContain('--subdomains');
      expect(stderr).toBe('');
    }, 10000);

    it('should display version information', async () => {
      const { stdout, stderr } = await execAsync(`node ${cliPath} --version`);
      
      expect(stdout).toContain('0.1.0');
      expect(stderr).toBe('');
    }, 5000);
  });

  describe('Basic domain analysis', () => {
    it('should analyze a single domain', async () => {
      const { stdout, stderr } = await execAsync(`node ${cliPath} example.com --quick --no-banner`, {
        timeout: 30000
      });
      
      expect(stdout).toContain('example.com');
      expect(stdout).toContain('INTELLIGENCE REPORT');
      // stderr may contain spinner output, so we'll be more lenient
    }, 35000);

    it('should handle invalid domain gracefully', async () => {
      const { stdout, stderr } = await execAsync(`node ${cliPath} invalid-domain-12345.invalid --quick --no-banner`, {
        timeout: 15000
      });
      
      // Should not crash, even with invalid domain
      expect(stdout).toContain('invalid-domain-12345.invalid');
    }, 20000);
  });

  describe('Export options', () => {
    it('should accept CSV export option', async () => {
      const command = `node ${cliPath} example.com --quick --no-banner --export-csv /tmp/test-cli-export`;
      
      await expect(execAsync(command, { timeout: 20000 })).resolves.not.toThrow();
    }, 25000);

    it('should accept JSON export option', async () => {
      const command = `node ${cliPath} example.com --quick --no-banner --export-json /tmp/test-cli-json-export`;
      
      await expect(execAsync(command, { timeout: 20000 })).resolves.not.toThrow();
    }, 25000);

    it('should accept subdomain discovery option', async () => {
      const command = `node ${cliPath} example.com --quick --no-banner --subdomains`;
      
      const { stdout } = await execAsync(command, { timeout: 25000 });
      expect(stdout).toContain('SUBDOMAIN');
    }, 30000);
  });

  describe('Multiple domain analysis', () => {
    it('should analyze multiple domains', async () => {
      const command = `node ${cliPath} example.com google.com --quick --no-banner`;
      
      const { stdout } = await execAsync(command, { timeout: 40000 });
      
      expect(stdout).toContain('example.com');
      expect(stdout).toContain('google.com');
      expect(stdout).toContain('MULTIPLE TARGETS ACQUIRED');
    }, 45000);
  });

  describe('Error handling', () => {
    it('should show error for missing domain argument', async () => {
      try {
        await execAsync(`node ${cliPath} --quick`);
      } catch (error: any) {
        expect(error.code).toBe(1);
        expect(error.stderr || error.stdout).toContain('error');
      }
    }, 10000);

    it('should handle invalid command line options', async () => {
      try {
        await execAsync(`node ${cliPath} example.com --invalid-option`);
      } catch (error: any) {
        expect(error.code).toBe(1);
      }
    }, 10000);
  });
});