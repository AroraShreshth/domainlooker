declare module 'whois' {
  interface LookupOptions {
    server?: string;
    follow?: number;
    timeout?: number;
    verbose?: boolean;
    [key: string]: unknown;
  }
  export function lookup(domain: string, callback: (err: Error | null, data: string) => void): void;
  export function lookup(domain: string, options: LookupOptions, callback: (err: Error | null, data: string) => void): void;
}
