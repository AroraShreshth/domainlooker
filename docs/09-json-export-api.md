# JSON export schema

`domainlooker --export-json <file>` writes a structured JSON document describing every domain in the run. The schema is defined in [`src/types/api-schema.ts`](../src/types/api-schema.ts).

## Top level

```jsonc
{
  "meta": {
    "version": "1.0.0",
    "timestamp": "2026-01-01T00:00:00.000Z",
    "requestId": "<uuid>",
    "executionTimeMs": 1234,
    "totalDomains": 1,
    "options": {
      "includeSubdomains": false,
      "includeNetworkScan": true,
      "quickScan": false,
      "verbose": false
    }
  },
  "data": [ /* one DomainAnalysisData per domain */ ]
}
```

## Per-domain (`data[]`)

Each entry has a top-level `status` (`success` | `partial` | `failed`) plus one block per data source. Every block carries its own `status` and is `null` (with an `error` string) when the lookup did not run or produced nothing.

| Field | Description |
| --- | --- |
| `whois` | Registrar, registration/expiry dates, name servers, `daysUntilExpiry` |
| `dns` | Records (A, AAAA, MX, NS, TXT, SOA) plus a `summary` with counts and `hasIpv4` / `hasIpv6` / `hasMail` flags |
| `ssl` | Certificate fields, `validation` (validity, days until expiry, expired, self-signed), and `security` (key size, protocol) |
| `network` | Open/filtered ports, identified services, and a summary of common vs. unusual ports |
| `subdomains` | Discovered names, per-source lists (certificate transparency, common names), and statistics |
| `threatAssessment` | `overallRisk`, a 0–100 `riskScore`, a list of `threats`, and de-duplicated `recommendations` |
| `sources` | Which method produced each block |

## Threat assessment

The `threatAssessment` block is a small set of factual, rule-based checks — it is not a reputation or malware feed. Current checks:

- Missing SSL certificate.
- SSL certificate expiring within 30 days (critical under 7).
- Domain registered within the last 30 days.
- More than five open ports.

Each check contributes to `riskScore`, which maps to `overallRisk` (`low` < 20 ≤ `medium` < 40 ≤ `high` < 70 ≤ `critical`).
