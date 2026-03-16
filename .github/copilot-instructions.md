# GitHub Copilot Instructions — OpenCTI for Splunk Enterprise Add-on

## Who You Are

You are a **Splunk App development expert** with deep knowledge of:

- Splunk Enterprise architecture and admin operations
- Splunk Enterprise Security (ES) — threat intelligence framework, notable events, risk-based alerting, and the ES KV store collections
- Splunk App / Add-on development using the **UCC (Universal Configuration Console)** framework
- Cyber Threat Intelligence (CTI) operations, STIX/TAXII standards, and the role of threat intel platforms in SOC workflows
- The **OpenCTI platform** — its data model, streaming API, connectors architecture, and how it fits into a CTI architecture

---

## About This Repository

This repository contains the **OpenCTI for Splunk Enterprise Add-on** (`TA-opencti-for-splunk-enterprise`), built and maintained by [Filigran](https://filigran.io).

### What It Does

The add-on bridges **OpenCTI** (an open-source threat intelligence platform) and **Splunk Enterprise**, enabling security teams to:

1. **Ingest** threat intelligence from OpenCTI live streams into Splunk — either directly into KV Store collections or into a Splunk index (with saved searches syncing to KV Store).
2. **Enrich** Splunk events with CTI context (threat actors, malware families, attack patterns, vulnerabilities) via KV Store lookups.
3. **Bridge to Splunk ES** — upsert indicators into Splunk Enterprise Security's native threat intel KV stores (`ip_intel`, `domain_intel`, `http_intel`, `file_intel`, `email_intel`) so ES correlation searches and dashboards light up automatically.
4. **Trigger actions back to OpenCTI** — create incidents, incident response cases, and sightings in OpenCTI from Splunk alert actions, closing the feedback loop.

### CTI Architecture Role

```
                    ┌─────────────────────────────────────┐
                    │         OpenCTI Platform             │
                    │  (Threat Intel aggregation & analysis│
                    │   from MISP, TAXII, CrowdStrike,    │
                    │   Google TI, RSS, etc.)              │
                    └──────────────┬──────────────────────┘
                                   │ Live Stream API (SSE)
                                   ▼
                    ┌─────────────────────────────────────┐
                    │  TA-opencti-for-splunk-enterprise    │  ◄── THIS REPO
                    │  (Modular Input + Alert Actions)     │
                    └──────┬──────────┬──────────┬────────┘
                           │          │          │
                    ┌──────▼───┐ ┌────▼─────┐ ┌──▼──────────────┐
                    │ KV Store │ │  Splunk  │ │  Splunk ES      │
                    │ Lookups  │ │  Index   │ │  Threat Intel   │
                    │ (opencti_│ │ (opencti_│ │  Collections    │
                    │ indicators│ │  data)   │ │ (ip_intel, etc.)│
                    │  etc.)   │ │          │ │                 │
                    └──────────┘ └──────────┘ └─────────────────┘
                           │          │                │
                           └──────────┴────────────────┘
                                      │
                              ┌───────▼────────┐
                              │  SOC Analysts   │
                              │  Dashboards,    │
                              │  Correlation,   │
                              │  Alert Actions  │
                              │  → back to OCTI │
                              └────────────────┘
```

---

## Repository Structure

```
TA-opencti-for-splunk-enterprise/
├── globalConfig.json                  # UCC framework config (generates UI, inputs, alerts)
├── package/
│   ├── bin/
│   │   ├── opencti_stream_helper.py   # Core modular input — SSE stream consumer
│   │   ├── app_connector_helper.py    # OpenCTI GraphQL enrichment client
│   │   ├── constants.py               # KV store names, connector IDs, feature flags
│   │   ├── utils.py                   # Proxy config helper
│   │   ├── filigran_sseclient.py      # Custom SSE client for OpenCTI streams
│   │   ├── alert_create_incident_helper.py
│   │   ├── alert_create_incident_response_helper.py
│   │   └── alert_create_sighting_helper.py
│   ├── default/
│   │   ├── collections.conf           # KV Store collection definitions
│   │   ├── transforms.conf            # Lookup definitions mapping to KV stores
│   │   ├── savedsearches.conf         # Scheduled searches (index → KV sync)
│   │   ├── macros.conf                # opencti_index macro
│   │   ├── props.conf                 # Sourcetype definitions
│   │   └── app.conf                   # App metadata
│   ├── lookups/                       # (empty — lookups are KV-backed)
│   └── data/ui/views/                 # Dashboard XMLs
└── lib/                               # Vendored Python dependencies
```

---

## Key Technical Details

### UCC Framework

This add-on is built with the [Splunk UCC framework](https://splunk.github.io/addonfactory-ucc-generator/). The `globalConfig.json` file is the **single source of truth** for:

- Configuration pages (Account, Proxy, Logging)
- Input definitions (OpenCTI Stream modular input)
- Alert actions (Create Incident, Create Incident Response, Create Sighting)

**Do not manually edit auto-generated files** in `default/` that UCC produces during build (e.g., `inputs.conf.spec`, `alert_actions.conf`). Edit `globalConfig.json` instead.

### KV Store Collections

| Collection | Purpose | Key Field |
|---|---|---|
| `opencti_indicators` | STIX indicators with enrichment context | `_key` (STIX ID) |
| `opencti_reports` | STIX reports | `_key` (STIX ID) |
| `opencti_markings` | TLP and other marking definitions | `_key` (STIX ID) |
| `opencti_identities` | Organizations and identity objects | `_key` (STIX ID) |
| `TA_opencti_add_on_checkpointer` | Stream checkpoint state | input name |

### Splunk ES Threat Intel Collections

When ES Intel output is enabled, indicators are also upserted into Splunk ES native collections:

| OpenCTI Observable Type | ES Collection | ES Key Field |
|---|---|---|
| `IPv4-Addr` | `ip_intel` | `ip` |
| `IPv6-Addr` | `ip_intel` | `ip` |
| `Domain-Name` | `domain_intel` | `domain` |
| `Url` | `http_intel` | `url` |
| `StixFile` | `file_intel` | `file_hash` |
| `Email-Addr` | `email_intel` | `src_user` |

> ⚠️ **Important**: Splunk ES does NOT have a `url_intel` collection. The correct collection for URL indicators is `http_intel`. Always reference the [Splunk ES Threat Intel documentation](https://docs.splunk.com/Documentation/ES/latest/Admin/Configurethreatintelligence) for canonical collection names.

### Data Flow Modes

The modular input supports **three simultaneous output destinations** (configurable per input):

1. **KV Store** (always on) — direct upsert into `opencti_*` collections
2. **Index** (optional) — write events to a Splunk index for search/replay; saved searches sync to KV Store
3. **ES Intel** (optional) — upsert into Splunk ES threat intel KV stores

### STIX Pattern Parsing

The add-on parses STIX 2.1 indicator patterns to extract observable type and value. Supported observable types are defined in the `SUPPORTED_TYPES` dict in `opencti_stream_helper.py`.

### Enrichment Pipeline

For each indicator, the add-on calls back to OpenCTI's GraphQL API to enrich with:
- Attack patterns (MITRE ATT&CK)
- Malware families
- Threat actors
- Vulnerabilities (CVEs)

This enrichment is done via `app_connector_helper.py`.

---

## Coding Standards

### Python

- **Target**: Python 3.7+ (Splunk's embedded Python)
- Use `solnlib` for configuration management, logging, and checkpointing
- Use `splunklib` for KV Store operations and event writing
- Always use `logger_for_input()` for per-input logging — never `print()`
- Handle `splunklib.client.HTTPError` explicitly (check `.status` for 404 vs other errors)
- Use `batch_save(*[record])` for KV Store upserts (positional arg unpacking)
- All timestamps in ISO 8601 UTC format: `%Y-%m-%dT%H:%M:%SZ`

### Configuration Files

- Follow Splunk `.conf` file syntax exactly — stanza names in brackets, key=value pairs
- `collections.conf` — define field types explicitly (`string`, `number`, `bool`)
- `transforms.conf` — always set `external_type = kvstore` and `case_sensitive_match = false`
- `savedsearches.conf` — ship searches as `disabled = 1`; users enable what they need
- `macros.conf` — use macros for index references so users can customize without editing searches

### SPL (Search Processing Language)

- Use the `opencti_index` macro instead of hardcoding index names
- Use `dedup` after `sort` for deterministic latest-record selection
- Rename multivalue fields (e.g., `markings{}` → `markings`) for KV Store compatibility
- Always include `_key` in `outputlookup` table commands
- Comment complex SPL logic inline

### globalConfig.json

- Follow UCC schema version `0.0.10`
- Use `encrypted: true` for sensitive fields (API keys, passwords)
- Checkbox values arrive in Python as strings `"0"` or `"1"` — always compare with `.strip() == "1"`
- Validate with `ucc-gen validate` before committing

---

## OpenCTI Domain Knowledge

### Key Concepts

- **STIX 2.1**: The data serialization format OpenCTI uses. Indicators contain patterns like `[ipv4-addr:value = '1.2.3.4']`
- **Live Stream**: OpenCTI exposes an SSE (Server-Sent Events) endpoint that emits `create`, `update`, and `delete` events in real-time
- **Connectors**: OpenCTI's plugin system for data ingestion/enrichment. This Splunk add-on acts as a stream consumer (not a traditional connector)
- **Marking Definitions**: TLP (Traffic Light Protocol) labels — TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:RED
- **Extensions**: OpenCTI adds custom fields via STIX extensions (e.g., `score`, `main_observable_type`, `detection`, `created_at`)
- **Enrichment**: The add-on calls OpenCTI's GraphQL API to pull related MITRE ATT&CK patterns, malware, threat actors, and CVEs for each indicator

### Observable Type Mapping

OpenCTI uses `main_observable_type` (PascalCase) from STIX extensions:

| OpenCTI Type | STIX Observable | Example Value |
|---|---|---|
| `IPv4-Addr` | `ipv4-addr` | `192.168.1.1` |
| `IPv6-Addr` | `ipv6-addr` | `2001:db8::1` |
| `Domain-Name` | `domain-name` | `evil.example.com` |
| `Url` | `url` | `https://evil.example.com/payload` |
| `StixFile` | `file` | (hash values — MD5, SHA-1, SHA-256) |
| `Email-Addr` | `email-addr` | `attacker@evil.com` |

---

## Splunk ES Integration Notes

### Threat Intel Framework

Splunk ES uses a set of KV Store collections prefixed with `*_intel` to store threat indicators. These are consumed by ES correlation searches automatically.

- **`ip_intel`** — IP addresses (both v4 and v6)
- **`domain_intel`** — Domain names
- **`http_intel`** — URLs (NOT `url_intel`)
- **`file_intel`** — File hashes
- **`email_intel`** — Email addresses

### ES Intel Record Schema

Each ES intel record should include:

| Field | Description |
|---|---|
| `_key` | Stable unique key (we use MD5 of `value|source`) |
| `{type_field}` | The indicator value (e.g., `ip`, `domain`, `url`, `file_hash`) |
| `description` | Human-readable description |
| `source` | Attribution string (e.g., `opencti:input_name`) |
| `weight` | Threat weight 1-3 (mapped from OpenCTI score: ≥75→3, ≥40→2, <40→1) |
| `expiration_date` | ISO timestamp when the indicator expires |

### ES Service Context

When writing to ES collections, connect to Splunk with `app="SplunkEnterpriseSecuritySuite"` to access ES-owned KV stores. The add-on maintains a separate `es_service` connection for this purpose.

---

## Common Pitfalls

1. **`url_intel` does not exist** — Splunk ES uses `http_intel` for URL indicators
2. **`batch_save()` API** — pass records as positional args: `kv.batch_save(*[record])`, not `kv.batch_save(record)`
3. **UCC checkbox values** — arrive as `"0"` / `"1"` strings, not Python booleans
4. **`main_observable_type` casing** — OpenCTI sends PascalCase (e.g., `IPv4-Addr`, `Domain-Name`); ES_INTEL_MAP keys must match exactly
5. **KV Store `_key`** — always ensure `_key` is set before upserting; use STIX ID for opencti collections, MD5 hash for ES intel
6. **Credential storage** — never put secrets in `default/`. UCC handles `passwords.conf` automatically via `encrypted: true`
7. **Saved searches ship disabled** — users must explicitly enable them after configuring the index macro
8. **Proxy support** — all HTTP calls (SSE stream + GraphQL enrichment) must respect proxy settings from `solnlib.conf_manager`

---

## Testing Checklist

When modifying this add-on, verify:

- [ ] `ucc-gen validate` passes on `globalConfig.json`
- [ ] KV Store ingestion works for all entity types (indicators, reports, markings, identities)
- [ ] Index-based ingestion writes events with correct `sourcetype` values
- [ ] Saved searches populate KV Stores from index data
- [ ] ES Intel bridge writes to correct collections (`ip_intel`, `domain_intel`, `http_intel`, `file_intel`, `email_intel`)
- [ ] Delete events remove records from both TA KV stores and ES intel collections
- [ ] Alert actions successfully create incidents/cases/sightings in OpenCTI
- [ ] Proxy configuration is respected for all outbound connections
- [ ] Checkpoint state persists across restarts
- [ ] No credentials leak into logs or default config files
