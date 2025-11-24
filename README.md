# TA-opencti-for-splunk-enterprise

**Version 1.0.0**  
**Author:** Filigran

---


## Overview

The **OpenCTI for Splunk Enterprise Add-on** provides a modular framework for integrating threat intelligence from [OpenCTI](https://www.opencti.io) into Splunk.  
It enables analysts to collect, normalize, and enrich OpenCTI indicators and observables, making them searchable within Splunk Enterprise for correlation, detection, and incident response.

---

## Key Features

- Modular inputs for ingesting OpenCTI data via the OpenCTI API.
- Support for multiple object types (Indicators, Observables, Relationships, Sightings).
- Pre-configured eventtypes, tags, and alert actions.
- Custom REST endpoints for configuration and health-checks.
- Automatic reload triggers for modular input changes.

---

## Installation

1. **Copy or install the app** into `$SPLUNK_HOME/etc/apps/TA-opencti-for-splunk-enterprise`.
2. **Restart Splunk** (recommended) to ensure all REST handlers and modular inputs register correctly.
3. **Configure your OpenCTI connection** through **Settings → Data Inputs → OpenCTI for Splunk Enterprise**.

---

## Configuration

| Setting                 | Description                                             |
| ----------------------- | ------------------------------------------------------- |
| **API URL**             | Base URL of your OpenCTI instance.                      |
| **API Token**           | Access token used for authentication.                   |
| **Collection Interval** | Frequency (in seconds) at which data is collected.      |
| **Object Types**        | Comma-separated list of OpenCTI entity types to ingest. |

Configuration parameters are stored securely in `local/passwords.conf`.  
Never ship credentials in `default/passwords.conf`.

---

## Index Configuration

If you plan to store OpenCTI data in a dedicated index, define one manually.

### For on-prem installs

Create the following stanza in `default/indexes.conf` or your deployment tooling:

```ini
[opencti]
homePath   = $SPLUNK_DB/opencti/db
coldPath   = $SPLUNK_DB/opencti/colddb
thawedPath = $SPLUNK_DB/opencti/thaweddb
# frozenTimePeriodInSecs = 15552000   # optional retention (180 days)
```

---

## Splunk Enterprise Security Integration

The add-on can expose OpenCTI indicators to the Splunk Enterprise Security (ES) Threat Intelligence Framework by populating an ES-compliant lookup called `opencti_threatintel`.

At a high level:

1. The modular input writes OpenCTI events into a Splunk index (for example, `opencti_stream`).
2. Normalization searches populate a catalog of indicators in the `opencti_indicators` KV store.
3. A scheduled search maps `opencti_indicators` into an ES-friendly lookup named `opencti_threatintel`.
4. ES is configured to treat `opencti_threatintel` as a threat intelligence source.

> **Note:** The `opencti_threatintel` lookup can be defined either in this add-on **or** in the ES app (`SA-ThreatIntelligence`).  
> A saved search running in the OpenCTI app can populate it as long as:
>
> - The lookup definition is shared **Global**, and
> - There is no other lookup with the same name shadowing it in the OpenCTI app.

### Prerquisites

- Splunk Enterprise Security installed on the search head where this add-on is installed.
- The OpenCTI modular input is configured and successfully ingesting data.
- The `opencti_indicators` KV store lookup is populated
- You have admin (or equivalent) permissions in Splunk and ES.

### 1. Create the `opencti_threatintel` KV Store lookup

1. In Splunk Web, go to **Settings ▸ Lookups ▸ Lookup definitions**.
2. Click **Add new** and create a KV Store lookup:
    - **Destination app:** `SA-ThreatIntelligence`
    - **Name:** `opencti_threatintel`
    - **Type:** KV Store
    - **KV store collection name:** `opencti_threatintel`
    - **Fields:** \_key, threat_key, threat_match_value, threat_type, threat_description, threat_group, threat_category, threat_first_seen, threat_last_seen, threat_confidence, threat_weight
3. After saving, click on the **Permissions** link for the `opencti_threatintel` lookup definition:
    - Set **Sharing** to **Global** so ES (in apps like `TA-opencti-for-splunk-enterprise`) can read it.

> If you prefer to manage collections via config files, you can instead define this collection in `collections.conf` and the lookup in `transforms.conf`.

---

### 2. Verify the `opencti_indicators` lookup

The shipped searches in this add-on maintain a canonical indicator lookup in the `opencti_indicators` KV store. ES integration builds on top of this lookup.

To verify it has data:

1. Open **Search & Reporting**.
2. Run:

   ```spl
   | inputlookup opencti_indicators
   | head 10
   ```

3. You should see one row per OpenCTI indicator, with fields such as id, name, pattern, value, score, confidence, main_observable_type, etc.

If this lookup is empty, review your OpenCTI inputs and the “Update OpenCTI Indicators Lookup” / “Nightly Rebuild OpenCTI Indicators Lookup” saved searches before proceeding.

---

### 3. Enable the Update Enterprise Security Threat Intelligence saved search

The OpenCTI add-on ships with a saved search called `Update Enterprise Security Threat Intelligence` that transforms the opencti_indicators catalog into the ES Threat Intelligence schema and writes it into the opencti_threatintel KV Store lookup.

Saved search properties (default):

- **Name:** `Update Enterprise Security Threat Intelligence`
- **App context:** TA-opencti-for-splunk-enterprise
- **Schedule:** _/5 _ \* \* \* (every 5 minutes)
- **Core SPL (conceptual):**

    - Reads from opencti_indicators via | inputlookup opencti_indicators
    - Maps OpenCTI fields into ES fields:

| ES field             | Source OpenCTI field(s)                                   | Notes                                                                                                 |
| -------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `threat_key`         | `id`                                                      | Stable identifier for the indicator (OpenCTI ID).                                                     |
| `threat_match_value` | `value`                                                   | Actual indicator value (IP, domain, URL, hash, email, etc.).                                          |
| `threat_type`        | `main_observable_type`, `type`                            | Mapped to ES types such as `ip_intel`, `domain_intel`, `url_intel`, `file_intel`, `email_intel`, etc. |
| `threat_description` | `name`                                                    | Human-readable name/title of the indicator.                                                           |
| `threat_group`       | `created_by`                                              | Origin or owner of the indicator (e.g., group, organization, actor).                                  |
| `threat_category`    | `labels`, `attack_patterns`, `malware`, `vulnerabilities` | Combined, multi-valued category/tactic/context information.                                           |
| `threat_first_seen`  | `valid_from`, `created`, `created_at`                     | First time the indicator was observed or became valid.                                                |
| `threat_last_seen`   | `valid_until`, `modified`, `updated_at`                   | Last time the indicator was observed or considered valid.                                             |
| `threat_confidence`  | `confidence`                                              | Numeric or ordinal confidence score from OpenCTI.                                                     |
| `threat_weight`      | `score`                                                   | Severity/priority score used by ES for weighting during correlation.                                  |

To verify or adjust this saved search:

1. In Splunk Web, go to **Settings ▸ Searches, reports, and alerts**.
2. Set App to TA-opencti-for-splunk-enterprise.
3. Locate `Update Enterprise Security Threat Intelligence`
4. Open the search:
    - Confirm it begins with | inputlookup opencti_indicators.
    - Confirm it ends with | outputlookup opencti_threatintel.
5. On the Schedule tab:
    - Ensure the search is enabled.
    - Adjust the schedule if needed (for example, to run less or more frequently based on your OpenCTI update cadence). 6. Save your changes.

On each run, this search rebuilds the ES Threat Intelligence KV from the enriched opencti_indicators KV.

---

### 4. Validate that opencti_threatintel is being populated

After the `Update Enterprise Security Threat Intelligence` search has run at least once:

1. Go to **Settings ▸ Lookups ▸ KV Store lookups**
2. Click Lookup contents for opencti_threatintel.
3. You should see rows of indicators with ES threat fields populated.

Or from search:

```
| inputlookup opencti_threatintel
| head 20
```

If you see no results:

- Confirm the saved search `Update Enterprise Security Threat Intelligence` has run successfully (check Activity ▸ Jobs).
- Confirm opencti_indicators contains data.
- Check lookup permissions:
- opencti_indicators and opencti_threatintel must both be shared Global and readable by ES.

---

### 5. Register opencti_threatintel as a Threat Intelligence source in ES

Once opencti_threatintel contains data, register it as a threat intelligence source:

1. In Splunk Enterprise Security, go to
   **Configure ▸ Data Enrichment ▸ Threat Intelligence Management** (menu name may vary slightly by ES version).
2. Under Threat Intelligence Sources, add a new source:
   **Type:** KV Store
   **Name:** OpenCTI Threat Intelligence (or any clear label)
   **Collection / Lookup:** `opencti_threatintel`
3. Enable the source.
4. Confirm that field mappings align with your lookup structure:
   **Indicator value** → threat_match_value
   **Type** → threat_type
   **Description / group / category** → threat_description, threat_group, threat_category
   **Temporal / scoring fields** → threat_first_seen, threat_last_seen, threat_confidence, threat_weight

At this point, ES correlation searches and threat intel–aware dashboards can use opencti_threatintel as a live feed of indicators from OpenCTI.

---

### 6. Troubleshooting

No indicators appear in ES correlation searches

- Check opencti_indicators:

```
| inputlookup opencti_indicators
| stats count
```

- Check the job history of `Update Enterprise Security Threat Intelligence` for errors.
- Confirm that opencti_threatintel has rows:

```
| inputlookup opencti_threatintel
| stats count
```

- Verify that ES has a Threat Intelligence source configured for opencti_threatintel.

Permission or lookup issues
Ensure: - opencti_indicators KV Store lookup is shared Global. - opencti_threatintel KV Store lookup is defined in SA-ThreatIntelligence and shared Global. - Verify that the roles used by ES and the OpenCTI add-on have read/write access to these lookups.

With these steps completed, OpenCTI becomes a first-class Threat Intelligence provider for Splunk Enterprise Security via the opencti_threatintel KV Store, maintained by the `Update Enterprise Security Threat Intelligence` saved search.
