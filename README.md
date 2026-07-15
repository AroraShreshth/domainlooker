# domainlooker

A fast command-line suite **and MCP server** for inspecting domains — WHOIS, DNS, SSL, open ports, and subdomains — with CSV and JSON export.

Every lookup runs in parallel, WHOIS uses RDAP (HTTP/JSON) first with a port-43 fallback, and timeouts are tight, so a full report typically lands in ~1–2 seconds.

[![npm version](https://badge.fury.io/js/domainlooker.svg)](https://www.npmjs.com/package/domainlooker)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Install

```bash
npm install -g domainlooker
```

## Usage

Run a full report on a domain:

```bash
domainlooker example.com
```

Or use a single-aspect subcommand when you only need one thing:

```bash
domainlooker whois example.com
domainlooker dns example.com
domainlooker ssl example.com
domainlooker ports example.com
domainlooker subdomains example.com
```

## Commands

| Command | Description |
| --- | --- |
| `inspect <domains...>` | Full report: WHOIS, DNS, SSL, ports, and advisories (this is the default, so `domainlooker <domain>` runs it) |
| `whois <domain>` | Registration data |
| `dns <domain>` | DNS records (A, AAAA, MX, NS, TXT, SOA) |
| `ssl <domain>` | SSL certificate details and expiry |
| `ports <domain>` | Scan common ports and identify services |
| `subdomains <domain>` | Discover subdomains via certificate transparency and common-name checks |
| `mcp` | Run as an MCP server over stdio (see below) |

### `inspect` options

```
-q, --quick              Skip the port scan
--subdomains             Also discover subdomains
-p, --parallel <number>  Domains to process in parallel (default: 3)
--export-csv <file>      Write results to a CSV file
--export-json <file>     Write results to a JSON file
-v, --verbose            Show underlying errors
```

## Examples

```bash
# Inspect several domains at once
domainlooker google.com github.com microsoft.com

# Quick scan plus subdomain discovery
domainlooker example.com --quick --subdomains

# Export to CSV and JSON
domainlooker example.com --export-csv report.csv --export-json report.json
```

## MCP server

`domainlooker mcp` runs an [MCP](https://modelcontextprotocol.io) server over stdio so AI agents can pull domain intelligence directly. Results are cached for a few minutes, so repeat calls return instantly.

Register it with any MCP client. For example:

```json
{
  "mcpServers": {
    "domainlooker": {
      "command": "domainlooker",
      "args": ["mcp"]
    }
  }
}
```

Tools exposed:

| Tool | Description |
| --- | --- |
| `inspect_domain` | Full intelligence for a domain (WHOIS, DNS, SSL, ports, advisories) as one structured object. Args: `domain`, `includePorts` (default true), `includeSubdomains` (default false). |
| `whois_lookup` | Registration data (RDAP with WHOIS fallback). |
| `dns_records` | A, AAAA, MX, NS, TXT, SOA records. |
| `ssl_certificate` | TLS certificate details and days until expiry. |
| `scan_ports` | Open TCP ports and identified services. |
| `find_subdomains` | Subdomains via certificate transparency and common names. |

## Example output

```
Report: example.com
═══════════════════

DNS records
───────────
┌───────────────┬───────────────────────────────┐
│ A             │ 93.184.216.34                 │
│ NS            │ a.iana-servers.net            │
│               │ b.iana-servers.net            │
└───────────────┴───────────────────────────────┘

SSL certificate
───────────────
┌────────────────────┬──────────────────────────┐
│ Subject            │ CN=example.com           │
│ Issuer             │ DigiCert Inc             │
│ Days until expiry  │ 180                      │
└────────────────────┴──────────────────────────┘

Advisories
──────────
No issues found.
```

## JSON export

`--export-json` writes a structured document (schema described in [docs/09-json-export-api.md](docs/09-json-export-api.md)) suitable for feeding into other tools or automation.

## Requirements

- Node.js 18 or higher
- Internet access for lookups

## License

MIT — see [LICENSE](LICENSE).
