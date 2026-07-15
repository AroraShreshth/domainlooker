import * as tls from 'tls';
import * as crypto from 'crypto';
import { SSLData } from '../types/index.js';

const DEFAULT_TIMEOUT_MS = 5000;

export class SSLService {
  async getCertificate(domain: string, port: number = 443, timeoutMs: number = DEFAULT_TIMEOUT_MS): Promise<SSLData> {
    return new Promise((resolve, reject) => {
      const options = {
        host: domain,
        port: port,
        servername: domain,
        rejectUnauthorized: false
      };

      const socket = tls.connect(options, () => {
        const cert = socket.getPeerCertificate(true);
        
        if (!cert || Object.keys(cert).length === 0) {
          socket.destroy();
          reject(new Error('No certificate found'));
          return;
        }

        const result: SSLData = {
          issuer: this.formatCertificateName(cert.issuer),
          subject: this.formatCertificateName(cert.subject),
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          fingerprint: cert.fingerprint,
          serialNumber: cert.serialNumber,
          signatureAlgorithm: (cert as any).sigalg,
          isValid: this.isCertificateValid(cert),
          daysUntilExpiry: this.getDaysUntilExpiry(cert.valid_to)
        };

        socket.destroy();
        resolve(result);
      });

      socket.on('error', (error) => {
        reject(error);
      });

      socket.setTimeout(timeoutMs, () => {
        socket.destroy();
        reject(new Error('SSL connection timeout'));
      });
    });
  }

  private formatCertificateName(certName: any): string {
    if (typeof certName === 'string') return certName;
    
    const parts = [];
    if (certName.CN) parts.push(`CN=${certName.CN}`);
    if (certName.O) parts.push(`O=${certName.O}`);
    if (certName.C) parts.push(`C=${certName.C}`);
    
    return parts.join(', ');
  }

  private isCertificateValid(cert: any): boolean {
    const now = new Date();
    const validFrom = new Date(cert.valid_from);
    const validTo = new Date(cert.valid_to);
    
    return now >= validFrom && now <= validTo;
  }

  private getDaysUntilExpiry(validTo: string): number {
    const expiryDate = new Date(validTo);
    const now = new Date();
    const diffTime = expiryDate.getTime() - now.getTime();
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  }
}