import { Socket } from 'net';
import { NetworkData } from '../types/index.js';

const DEFAULT_PORT_TIMEOUT_MS = 1200;

export interface NetworkScanOptions {
  extended?: boolean;
  /** Per-port connect timeout (ms). All ports are scanned concurrently, so this
   *  also bounds the whole scan's worst case (a fully firewalled host). */
  timeoutMs?: number;
}

export class NetworkService {
  private readonly commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995];
  private readonly extendedPorts = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3389, 5432, 5900, 8080, 8443];

  async scanPorts(domain: string, extended: boolean = false, timeoutMs: number = DEFAULT_PORT_TIMEOUT_MS): Promise<number[]> {
    const ports = extended ? this.extendedPorts : this.commonPorts;
    const openPorts: number[] = [];

    const scanPromises = ports.map(port => this.scanPort(domain, port, timeoutMs));
    const results = await Promise.allSettled(scanPromises);

    results.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value) {
        openPorts.push(ports[index]);
      }
    });

    return openPorts.sort((a, b) => a - b);
  }

  private async scanPort(host: string, port: number, timeoutMs: number): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = new Socket();

      const timeout = setTimeout(() => {
        socket.destroy();
        resolve(false);
      }, timeoutMs);

      socket.connect(port, host, () => {
        clearTimeout(timeout);
        socket.destroy();
        resolve(true);
      });

      socket.on('error', () => {
        clearTimeout(timeout);
        resolve(false);
      });
    });
  }

  async getNetworkInfo(domain: string, options: NetworkScanOptions = {}): Promise<NetworkData> {
    const result: NetworkData = {};

    try {
      result.openPorts = await this.scanPorts(domain, options.extended ?? false, options.timeoutMs ?? DEFAULT_PORT_TIMEOUT_MS);
      result.services = this.identifyServices(result.openPorts);
    } catch (error) {
      console.error('Network scan error:', error);
    }

    return result;
  }

  private identifyServices(ports: number[]): Array<{ port: number; protocol: string; service: string; version?: string }> {
    const serviceMap: { [key: number]: { protocol: string; service: string } } = {
      21: { protocol: 'TCP', service: 'FTP' },
      22: { protocol: 'TCP', service: 'SSH' },
      23: { protocol: 'TCP', service: 'Telnet' },
      25: { protocol: 'TCP', service: 'SMTP' },
      53: { protocol: 'UDP/TCP', service: 'DNS' },
      80: { protocol: 'TCP', service: 'HTTP' },
      110: { protocol: 'TCP', service: 'POP3' },
      135: { protocol: 'TCP', service: 'RPC' },
      139: { protocol: 'TCP', service: 'NetBIOS' },
      143: { protocol: 'TCP', service: 'IMAP' },
      443: { protocol: 'TCP', service: 'HTTPS' },
      445: { protocol: 'TCP', service: 'SMB' },
      993: { protocol: 'TCP', service: 'IMAPS' },
      995: { protocol: 'TCP', service: 'POP3S' },
      1433: { protocol: 'TCP', service: 'MSSQL' },
      3389: { protocol: 'TCP', service: 'RDP' },
      5432: { protocol: 'TCP', service: 'PostgreSQL' },
      5900: { protocol: 'TCP', service: 'VNC' },
      8080: { protocol: 'TCP', service: 'HTTP-Alt' },
      8443: { protocol: 'TCP', service: 'HTTPS-Alt' }
    };

    return ports.map(port => ({
      port,
      protocol: serviceMap[port]?.protocol || 'TCP',
      service: serviceMap[port]?.service || 'Unknown'
    }));
  }
}