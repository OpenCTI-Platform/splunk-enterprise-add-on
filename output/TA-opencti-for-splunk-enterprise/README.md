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
| Setting | Description |
|----------|--------------|
| **API URL** | Base URL of your OpenCTI instance. |
| **API Token** | Access token used for authentication. |
| **Collection Interval** | Frequency (in seconds) at which data is collected. |
| **Object Types** | Comma-separated list of OpenCTI entity types to ingest. |

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