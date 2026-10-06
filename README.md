# OpenCTI for Splunk Enterprise

Version 1.1.1  
Author: Filigran  
Package: TA-opencti-for-splunk-enterprise


## Overview

The **OpenCTI for Splunk Enterprise Add-on** provides a modular framework for integrating threat intelligence from [OpenCTI](https://filigran.io/platforms/opencti/) into Splunk.  
It enables analysts to collect, normalize, and enrich OpenCTI indicators and observables, making them searchable within Splunk Enterprise for correlation, detection, and incident response.


## Key Features

- Modular inputs for ingesting OpenCTI data via the OpenCTI Stream API.
- Ability to trigger OpenCTI actions in response of Alerts and to investigate them directly in OpenCTI
- Support for multiple object types (Indicators, Observables, Relationships, Sightings).

---

## Installation

### Installation from Splunkbase

1. Log in to the Splunk Web UI and navigate to "Apps" and click on "Find more Apps"
2. Search for "OpenCTI for Splunk Enterprise Add-on"
3. Click Install
   The app is installed

### Installing from file through the UI

1. Download latest version of the Splunk App: [TA-opencti-for-splunk-enterprise-1.1.1.tar.gz](https://github.com/OpenCTI-Platform/splunk-enterprise-add-on/releases/download/1.1.1/TA-opencti-for-splunk-enterprise-1.1.1.tar.gz)
2. Log in to the Splunk Web UI and navigate to "Apps" and click on "Manage Apps"
3. Click "Install app from file"
4. Choose file and select the "TA-opencti-for-splunk-enterprise-1.1.1.tar.gz" file
5. Click on Upload
   The app is installed

---

## General Configuration

### OpenCTI user account

Before configuring the App, we strongly recommend that you create a dedicated account in OpenCTI with the same properties as for a connector service account.
To create this service account, please refer to [Create a Service Account](https://docs.opencti.io/latest/administration/users/?h=service+account#create-a-service-account) documentation.

### General Add-On settings

1. Navigate to Splunk Web UI home page, open the "OpenCTI for Splunk Enterprise Add-on" and navigate to "Configuration" page.
2. Click on "Account" tab and complete the form with the required settings:

| Parameter                  | Description                                                      |
|----------------------------|------------------------------------------------------------------|
| `OpenCTI URL`              | The URL of the OpenCTI platform (A HTTPS connection is required) |
| `OpenCTI API Key`          | The API Token of the previously created user                     |

![](./.github/img/addon_settings.png "Add-on settings")

Configuration parameters are stored securely in `local/passwords.conf`.  
Never ship credentials in `default/passwords.conf`.

If a proxy configuration is required to connect to OpenCTI platform, you can configure it on the Proxy page

| Parameter        | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `Enable Proxy`   | Determines whether a proxy is required to communicate with OpenCTI platform |
| `Proxy Type`     | The type of proxy to use                                                    |
| `Proxy Host`     | The proxy hostname or IP address                                            |
| `Proxy Port`     | The proxy port                                                              |
| `Proxy Username` | An optional proxy username                                                  |
| `Proxy Password` | An optional proxy password                                                  |

### Security Platform settings

The add-on identifies this Splunk deployment in OpenCTI as a **Security Platform** of type SIEM. The
hunt evidence of the add-on (sightings of the hunt targets) is made on it. Configure it on the
"Security Platform" tab of the Configuration page:

| Parameter                                | Description                                                                                                                                  | Default            |
|------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|--------------------|
| `Security Platform ID`                   | Id (internal or STIX) of an existing OpenCTI Security Platform. Takes precedence over the name                                               | empty              |
| `Create the Security Platform`           | When no id is set, find the Security Platform by name, or create it (type SIEM)                                                               | enabled            |
| `Security Platform name`                 | Name used to find or create it                                                                                                               | `Splunk <server>`  |
| `Feature detection cache (minutes)`      | How long the capabilities read from the OpenCTI GraphQL schema are cached                                                                     | 60                 |

The resolved Security Platform is cached in the KV Store (`opencti_addon_state`) and shared by every
search head of a cluster, so members with different server names keep one Security Platform. Without a
configured name, the first default name recorded in that collection is used by every member, so members
resolving it for the first time at the same moment create one platform, not one each.

**OpenCTI account permissions.** The account of the add-on needs the capabilities of a connector service
account (bundle push and connector registration) plus "Knowledge: create / update" for the evidence
attachment to the hunt runs and the Security Platform creation.

## OpenCTI Data Inputs Configuration

The "OpenCTI for Splunk Enterprise Add-on" enables Splunk to be feed with intelligence exposed through an OpenCTI live stream. 
To do this, the add-on implements and manages Splunk modular inputs.

When configuring a modular input, you have two options for storing intelligence data:
- Write directly to dedicated KV Store collections defined by the application
- Write to a Splunk index, which will then propagate the data to a KV Store using saved searches


### KV Store Ingestion Configuration

The KV Store data input type mode allows pre-defined KV Store to be directly fed with intelligence exposed by the OpenCTI live stream.

![](./.github/img/kvstore_based_ingestion.png "KV Store based ingestion")

Proceed as follows to enable the ingestion of data in pre-defined KV Store:

1. From the "OpenCTI for Splunk Enterprise Add-on" sub menus, select the "Inputs" sub menu.
2. Click on "Create new input" button.
3. Complete the form with the following settings:

| Parameter     | Description                                                                                                    |
|---------------|----------------------------------------------------------------------------------------------------------------|
| `Name`        | Unique name for the input being configured                                                                     |
| `Interval`    | Time interval of input in seconds. Leave as default (0) to allow continuous execution of the ingestion process |
| `Index`       | Leave empty. Not applicable when writing directly to KV Store                                                  |
| `Stream Id`   | The Live Stream ID of the OpenCTI stream to consume                                                            |
| `Import from` | The number of days to go back for the initial data collection (default: 30) (optional)                         |
| `Input Type`  | Select KV Store entry                                                                                          |

4. Once the Input parameters have been correctly configured click "Add".

![](./.github/img/input_config_kvstore.png "KV Store Input Configuration")

5. Validate the newly created Input and ensure it's set to "Enabled".

As soon as the input is created, the ingestion of data begins.

Here are the KV Store names used to store intelligence: 
- opencti_indicators: store STIX indicators and related context information (related threat actors, vulnerabilities, malware, attack patterns...)
- opencti_reports: store STIX reports
- opencti_markings: store STIX markings definitions
- opencti_identities: store STIX identities definitions

You can monitor the import of indicators using the following Splunk SPL query that list all indicators ingested in the 'opencti_indicators' KV Store:

```
| inputlookup opencti_indicators
```

You can also consult the "Monitoring Dashboard" which gives you an overview of indicators ingested in the 'opencti_indicators' KV Store.

![](./.github/img/indicators_dashboard.png "Indicators Dashboard")

The ingestion process can also be monitored by consulting the log file ```ta-opencti-for-splunk-enterprise_{DATA_INPUT_NAME}.log``` present in the directory ```$SPLUNK_HOME/var/log/splunk/```

---
### Index-Based Ingestion Configuration (Required for Saved Searches)

When using **Index mode** ingestion, OpenCTI data is first written to a Splunk index and then synchronized into KV Store collections via saved searches.  
![](./.github/img/index_based_ingestion.png "Index based ingestion")

This section explains **how to define the index**, **configure macros**, and **enable the required saved searches**.


#### 1. Choose or Create a Splunk Index

By default, the add-on **does not assume a fixed Index name**.

#### Recommended default index
```
opencti_data
```
#### Create a dedicated index (recommended)

In Splunk Web:

1. Go to **Settings ▸ Indexes**
2. Click **New Index**
3. Set:
   - **Index name:** `opencti_data`
   - Leave other settings at defaults (or align with your data retention policy)
4. Save

> ⚠️ If you choose a **custom index name**, you must update the OpenCTI macro configuration (see below).

---

#### 2. Configure the OpenCTI Modular Input (Index Mode)

1. From the "OpenCTI for Splunk Enterprise" Add-on sub menus, select the "Inputs" sub menu.
2. Click on "Create new input" button.
3. Complete the form with the following settings:

| Parameter     | Description                                                                                                    |
|---------------|----------------------------------------------------------------------------------------------------------------|
| `Name`        | Unique name for the input being configured                                                                     |
| `Interval`    | Time interval of input in seconds. Leave as default (0) to allow continuous execution of the ingestion process |
| `Index`       | `opencti_data` (or your custom index)                                                                          |
| `Stream Id`   | The Live Stream ID of the OpenCTI stream to consume                                                            |
| `Import from` | The number of days to go back for the initial data collection (default: 30) (optional)                         |
| `Input Type`  | Select `Index entry`                                                                                           |

![](./.github/img/input_config_index.png "Index based Input Configuration")

4. Once the Input parameters have been correctly configured click "Add".

Once enabled:
- Each **OpenCTI stream event** is written as a **Splunk event**
- Events are **append-only**
- The same indicator may appear multiple times as it evolves over time

#### Event metadata

| Field        | Value                                       |
|--------------|---------------------------------------------|
| `source`     | `opencti`                                   |
| `sourcetype` | `opencti:indicator`, `opencti:report`, etc. |

---

#### 3. Configure the OpenCTI Index Macro (Required)

All shipped saved searches rely on a macro to locate OpenCTI data.

#### Macro name

```
opencti_index
```

#### Default definition

```
index=opencti_data
```

#### How to configure

1. Go to **Settings ▸ Advanced Search ▸ Search macros**
2. Locate `opencti_index`
3. Edit the macro definition:
```
index=<YOUR_INDEX_NAME>
```
4. Save

> ⚠️ If this macro is not updated correctly:
> - Saved searches will return **zero results**
> - KV Store synchronization will silently fail

---

#### 4. Enable Required Saved Searches (Index → KV Store Sync)

Index mode relies on scheduled searches to populate KV Store collections.

#### Required saved searches

| Saved Search Name                           | Purpose                                            |
|---------------------------------------------|----------------------------------------------------|
| `Update OpenCTI Indicators Lookup`          | Sync indicators into `opencti_indicators` KV Store |
| `Update OpenCTI Reports Lookup`             | Sync reports into `opencti_reports`                |
| `Nightly Rebuild OpenCTI Indicators Lookup` | Full rebuild safety net                            |

#### Enable them

1. Go to **Settings ▸ Searches, reports, and alerts**
2. Set **App context** to `TA-opencti-for-splunk-enterprise`
3. Enable:
- `Update OpenCTI Indicators Lookup`
- `Update OpenCTI Reports Lookup`
4. Verify schedules are enabled (default is sufficient)

---

#### 5. Data Flow Summary (Index Mode)
```
OpenCTI Stream
↓
Splunk Index (opencti_data)
↓
Saved Searches
↓
KV Store Collections
↓
Dashboards / Alert Actions
```
---

#### 6. Common Failure Modes (and How to Avoid Them)

| Issue                       | Cause                       | Fix                    |
|-----------------------------|-----------------------------|------------------------|
| No indicators in dashboards | Macro points to wrong index | Update `opencti_index` |
| KV Stores empty             | Saved searches disabled     | Enable saved searches  |
| Duplicate indicators        | Expected behavior           | Events are versioned   |

---

#### 7. Verification Checklist

Run these searches to confirm everything is working:

#### Index ingestion
```
`opencti_index`
| stats count by sourcetype
```

#### KV Store population

```
| inputlookup opencti_indicators
| head 10
```

## OpenCTI custom alert actions

You can use the "OpenCTI for Splunk Enterprise" to create custom alert actions that automatically create 'incidents' or/and 'incident response cases' or/and 'sighting' in response to alert trigger by Splunk.

### Create an incident or/and an incident response case or/and a sighting in OpenCTI

You can create an incident or an incident response case in OpenCTI from a custom alert action.
1. Write a Splunk search query.
2. Click Save As > Alert.
3. Fill out the Splunk Alert form. Give your alert a unique name and indicate whether the alert is a real-time alert or a scheduled alert.
4. Under Trigger Actions, click Add Actions.
5. From the list, select "OpenCTI - Create Incident" if you want the alert to create an incident in OpenCTI or "OpenCTI - Create Incident Response" if you want to create an incident response case in OpenCTI or "OpenCTI - Create Sighting" if you want to create a sighting in OpenCTI.

![](./.github/img/alert_actions.png "Custom Alert Actions")

6. To create and incident or an incident response case, complete the form with the following settings:

| Parameter                | Description                                           | Scope                             |
|--------------------------|-------------------------------------------------------|-----------------------------------|
| `Name`                   | Name of the incident                                  | Incident & Incident response case |
| `Description`            | Description of the incident or incident response case | Incident & Incident response case |                              
| `Type`                   | Incident Type or incident response case type          | Incident & Incident response case |                              
| `Severity`               | Severity of the incident or incident response case    | Incident & Incident response case | 
| `Priority`               | Priority of the incident response case                | Incident response case            | 
| `Labels`                 | Labels (separated by a comma) to be applied           | Incident & Incident response case | 
| `TLP`                    | Markings to be applied                                | Incident & Incident response case | 
| `Observables extraction` | Method for extracting observables                     | Incident & Incident response case | 

7. To create a sighting, complete the form with the following settings:

| Parameter                | Description                                                   | Scope      |
|--------------------------|---------------------------------------------------------------|------------|
| `Sighting Of (value)`    | Value of what was sighted                                     | Sighting   |
| `Sighting Of (type)`     | Type of what was sighted (URL, Domain, IPV4, IPV6, File Hash) | Sighting   |                              
| `Where Sighted (value)`  | Value of the 'System' or 'Organization' that saw the sighting | Sighting   |                              
| `Where Sighted (type)`   | 'System' or 'Organization' that saw the sighting              | Sighting   | 
| `Labels`                 | Labels (separated by a comma) to be applied                   | Sighting   | 
| `TLP`                    | Markings to be applied                                        | Sighting   | 

You can use [Splunk "tokens"](https://docs.splunk.com/Documentation/Splunk/9.2.2/Alert/EmailNotificationTokens#Result_tokens) as variables in the form to contextualize the data imported into OpenCTI.
Tokens represent data that a search generates. They work as placeholders or variables for data values that populate when the search completes.

Example of a configuration to create an incident in OpenCTI

![](./.github/img/alert_example.png "Alert Example")

### Observables extraction

To extract and model alert fields as OpenCTI observables attached to the incident or incident response case, the Add-on purpose two methods describe below.

#### CIM model

The “CIM model” method is based on the definition of CIM model fields. With this method, the Add-on will extract all the following fields and model them as follows:

| CIM Field         | Observable type                     |
|-------------------|-------------------------------------|
| `url`             | URL observable                      | 
| `url_domain`      | Domain observable                   |                       
| `user`            | User account observable             |                            
| `user_name`       | User account observable             | 
| `user_agent`      | User agent Observable               |
| `http_user_agent` | User agent Observable               |
| `dest`            | IPv4 or IPv6 or Hostname observable |
| `dest_ip`         | IPv4 or IPv6 observable             |
| `src`             | IPv4 or IPv6 or Hostname observable |
| `src_ip`          | IPv4 or IPv6 observable             |
| `file_hash`       | File observable                     |
| `file_name`       | File observable                     |


#### Field mapping

The “Field mapping” method searches for event fields starting with the string “octi_” and ending with an observable type.
The following list describe list of supported fields:

| OCTI Field                         | Observable type                       |
|------------------------------------|---------------------------------------|
| `octi_ip`                          | IPv4 or IPv6 observable               | 
| `octi_url`                         | URL observable                        |
| `octi_domain`                      | Domain observable                     |                       
| `octi_hash`                        | File observable                       |                       
| `octi_email_addr`                  | Email address observable              |                       
| `octi_user_agent`                  | User agent observable                 |                       
| `octi_mutex`                       | Mutex observable                      |                       
| `octi_text`                        | Text observable                       |                       
| `octi_windows_registry_key`        | Windows Registry Key observable       |                       
| `octi_windows_registry_value_type` | Windows Registry Key Value observable |                       
| `octi_directory`                   | Directory observable                  |                       
| `octi_email_message`               | Email message observable              |    
| `octi_file_name`                   | File observable                       |    
| `octi_mac_addr`                    | MAC address observable                | 
| `octi_user_account`                | User account address observable       |    

You can use the Splunk ```eval``` command to create a new field based on the value of another field.

Example:

```sourcetype=* | lookup opencti_indicators value as url_domain OUTPUT id as match_ioc_id | search match_ioc_id=* | eval octi_domain=url_domain | eval octi_url=url ```


Logs related to OpenCTI customer alerts are available in the following two log file:

```$SPLUNK_HOME/var/log/splunk/opencti_create_incident_modalert.log```

```$SPLUNK_HOME/var/log/splunk/opencti_create_incident_response_modalert.log```

---

## OpenCTI program compatibility

The add-on takes part in the autonomous hunting of OpenCTI: hunt searches run in Splunk report their
results as evidence of the OpenCTI hunt run, sighted on the named Splunk Security Platform.

### Compatibility matrix

The add-on reads the OpenCTI GraphQL schema once per platform (cached in the KV Store, see
`Feature detection cache`) and enables each capability only where the platform provides it. Missing
capabilities are skipped with one log line such as
`Hunt evidence attachment to the run: skipped, the OpenCTI platform (<version>) does not provide the hunt evidence write-back (huntRunEvidenceAdd)`.

| Add-on capability                                            | OpenCTI capability (detected)                                    | OpenCTI releases without it          |
|--------------------------------------------------------------|------------------------------------------------------------------|--------------------------------------|
| Ingestion, enrichment, Create Incident / Case / Sighting     | live streams, `stixBundlePush`                                   | always available                     |
| Splunk Security Platform (configured or auto-created)        | `securityPlatformAdd`, `securityPlatforms`                       | hunt evidence sighted on the Splunk host identity |
| Hunt evidence linked to the run                              | `huntRun` (+ `huntRunEvidenceAdd`)                               | evidence sent without the run link   |

### Hunts

#### Report hunt evidence

The "OpenCTI - Report hunt evidence" alert action reports the results of a hunt search as evidence of
an OpenCTI hunt run:

| Parameter                | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| `Hunt run ID`            | Id of the OpenCTI hunt run, usually a field of the results (`$result.hunt_run_id$`) |
| `Count`                  | Number of matching events of the result (`$result.count$`)                  |
| `Observables Extraction` | `CIM Model` (default) or `Field Mapping`, as for the incident actions        |
| `Labels`, `TLP`          | Labels and marking of the evidence                                          |

For each result, the action creates an Observed-Data over the extracted observables (`number_observed` =
count) and a sighting of each target of the hunt (indicators, attack patterns, threats) on the Splunk
Security Platform; every object carries `x_opencti_hunt_run_id` and names the run in its description.
Ids are the ones OpenCTI derives from its key fields (the objects of an Observed-Data; the target, the
platform and the window of a sighting): OpenCTI merges the same observation reported again, by the
same or another run, into one object.
When the platform supports it, the objects are attached to the hunt run (`huntRunEvidenceAdd`, which
carries the hit count and time of each report), so each run lists its own evidence even when it shares
an object with another run. The bundle is ingested asynchronously by the OpenCTI workers: the action
waits up to 15 seconds for the objects, and the ones still not ingested are attached by the next
evidence report of the same run (within a day; evidence OpenCTI never ingests is dropped after a day by the
next evidence report of any run); that deferral is not a failure. A link OpenCTI rejects
fails the result (the alert action reports it) and is retried by the next evidence report of the run,
as is evidence that cannot be deferred because the KV Store is unavailable.

Example hunt search, run with the id of the hunt run OpenCTI created:

```
| tstats count min(_time) AS first_seen max(_time) AS last_seen from datamodel=Network_Resolution.DNS
    where `opencti_hunt_scope` DNS.query="*.example-c2.top" by DNS.query DNS.src
| rename DNS.query AS query DNS.src AS src
| eval hunt_run_id="<hunt run id>"
```

#### OpenCTI internal-hunt/splunk connector

The OpenCTI hunt connector for Splunk translates the Sigma logic of hunts into SPL with pySigma and runs
it through the Splunk REST search API. Recommendations:

- **Service account**: a dedicated Splunk user for the connector, with a role allowing `search` and
  `rest_properties_get` only, searchable indexes restricted to the hunt scope, a search quota
  (`srchJobsQuota`, `srchDiskQuota`) and a time window limit (`srchTimeWin`). Use a Splunk token, not a
  password.
- **Scope**: set the role default and allowed indexes to the same indexes as the `opencti_hunt_scope`
  macro, and use the macro in hunt searches written by hand, so a hunt never reads more than intended.
- **REST endpoint**: `https://<search head>:8089/services/search/v2/jobs/export` (or `search/jobs`
  for long runs); the connector needs network access to the management port.
- **pySigma pipelines**: `splunk_windows` for Windows event logs, `splunk_cim_data_model` (or the CIM
  pipeline of your backend version) when your data is CIM-normalized; the CIM field names (`dest`,
  `src`, `user`, `process`, `file_hash`, `query`, `url`...) are those of the Splunk Common Information
  Model.
- **Evidence**: the connector reports the hits of the runs it executes; hunts implemented as Splunk
  saved searches report through the "OpenCTI - Report hunt evidence" alert action above.

The action writes its log to `$SPLUNK_HOME/var/log/splunk/opencti_report_hunt_evidence_modalert.log` and exits
with a non-zero code when at least one result could not be reported, so failures show in the Splunk alert
action status (`index=_internal sourcetype=splunkd component=sendmodalert`).

### Monitoring

The Monitoring dashboard has a **Hunts** tab: hunt evidence reported by the "OpenCTI - Report hunt evidence"
alert action, and its errors.
