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
- Dissemination assurance: Splunk is a named Security Platform in OpenCTI, and the add-on writes back
  which indicators are deployed, how often they hit, and whether the OpenAEV benign tests of IOC
  validation requests were detected. See [OpenCTI program compatibility](#opencti-program-compatibility).
- Every program feature is detected from the OpenCTI schema: on OpenCTI releases without it the add-on
  behaves as before and logs why the feature is skipped.

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
deployments, hits and IOC validation proofs of the add-on are attached to it. Configure it on the
"Security Platform" tab of the Configuration page:

| Parameter                                | Description                                                                                                                                  | Default            |
|------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|--------------------|
| `Security Platform ID`                   | Id (internal or STIX) of an existing OpenCTI Security Platform. Takes precedence over the name                                               | empty              |
| `Create the Security Platform`           | When no id is set, find the Security Platform by name, or create it (type SIEM)                                                               | enabled            |
| `Security Platform name`                 | Name used to find or create it                                                                                                               | `Splunk <server>`  |
| `Deployment write-back`                  | Report the deployment status of every indicator ingested by the modular input                                                                | enabled            |
| `Write-back batch size`                  | Deployment reports per OpenCTI call (1-500)                                                                                                   | 100                |
| `Write-back rate limit`                  | Maximum write-back calls per minute (1-6000)                                                                                                  | 60                 |
| `IOC validation write-back`              | Write the outcomes decided by the "OpenCTI - IOC validation proof" search back to OpenCTI                                                     | enabled            |
| `IOC validation grace period (minutes)`  | Delay after the end of a validation test before a missing hit is reported as missed                                                           | 30                 |
| `Feature detection cache (minutes)`      | How long the capabilities read from the OpenCTI GraphQL schema are cached                                                                     | 60                 |

The resolved Security Platform is cached in the KV Store (`opencti_addon_state`) and shared by every
search head of a cluster, so members with different server names keep one Security Platform. Without a
configured name, the first default name recorded in that collection is used by every member, so members
resolving it for the first time at the same moment create one platform, not one each.

**OpenCTI account permissions.** The account of the add-on needs the capabilities of a connector service
account (bundle push and connector registration) plus "Knowledge: create / update" for the write-back
mutations and the Security Platform creation.

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

The add-on speaks natively the dissemination assurance of OpenCTI: an indicator is not just disseminated,
it is deployed on a named Splunk Security Platform, its hits are counted, and OpenAEV benign tests prove
the detection.

### Compatibility matrix

The add-on reads the OpenCTI GraphQL schema once per platform (cached in the KV Store, see
`Feature detection cache`) and enables each capability only where the platform provides it. Missing
capabilities are skipped with one log line such as
`IOC validation proof: skipped, the OpenCTI platform (<version>) does not provide the IOC validation requests (iocValidationRequests)`.

| Add-on capability                                            | OpenCTI capability (detected)                                    | OpenCTI releases without it          |
|--------------------------------------------------------------|------------------------------------------------------------------|--------------------------------------|
| Ingestion, enrichment, Create Incident / Case / Sighting     | live streams, `stixBundlePush`                                   | always available                     |
| Splunk Security Platform (configured or auto-created)        | `securityPlatformAdd`, `securityPlatforms`                       | the features below are skipped       |
| Deployment write-back, reconciliation                        | `indicatorReportDeployment(s)`, `deployed-on`                    | skipped                              |
| Indicator hits                                               | `indicatorReportHits`                                            | reported as sightings on the Security Platform |
| IOC validation proof                                         | `iocValidationRequests` (+ `iocValidationReportResults`)         | skipped (bundle write-back without the results mutation) |

The custom search commands (`openctireporthits`, `openctivalidation`, `openctireconcile`) declare `python.required = 3.13`, the Python runtime of Splunk Enterprise 10: the
libraries the add-on ships (stix2 3.0.2) need Python 3.10 or later, so the Python 3.9 runtime is not
supported.

### Dissemination assurance: deployments, hits and IOC validation proof

#### Deployment write-back

When `Deployment write-back` is enabled, the modular input reports to OpenCTI the deployment state of every
indicator it writes, on the Splunk Security Platform:

| Splunk event                                                   | Reported status | External id                                |
|----------------------------------------------------------------|-----------------|--------------------------------------------|
| Indicator written to `opencti_indicators` (KV Store mode)       | `deployed`      | `kvstore:opencti_indicators/<_key>`         |
| Indicator event written to the index (index mode)              | `deployed`      | `index:<index>/<indicator STIX id>`         |
| Delete event, or update of a revoked indicator                 | `removed` (index mode also deletes the `opencti_indicators` entry, keyed by the STIX id by the lookup searches) | same |
| Same, with `valid_until` in the past                            | `removed` with `removed_at = valid_until` (OpenCTI reserves `expired` to removals no consumer confirmed) | same |
| KV Store or index write failure                                | `failed` with the error message | same                         |
| Drift repaired by `openctireconcile`                           | `deployed` or `removed` | the external id OpenCTI holds, else the one the stream input reported (`opencti_deployments`), else `index:<index>/<indicator STIX id>` for index-mode lookup entries, else `kvstore:opencti_indicators/<_key>` |

Reports are queued, deduplicated per indicator (the last state wins), sent in batches of
`Write-back batch size` under the `Write-back rate limit`, and retried with a backoff (15 s, 60 s) before
being abandoned and logged; OpenCTI applies them idempotently. The last report per indicator is kept in
the `opencti_deployments` collection (Monitoring dashboard).

#### Reconciliation

The `OpenCTI - Reconcile indicator deployments` saved search (`| openctireconcile`, hourly) compares
`opencti_indicators` with the `deployed-on` relationships OpenCTI knows for the Splunk Security Platform
and repairs the drift (indicators deployed in Splunk but unknown or not live in OpenCTI, live in OpenCTI
but absent, revoked or expired in Splunk). `| openctireconcile refresh=true` also re-reports indicators
already in sync, which refreshes `last_sync_at` in OpenCTI. In index mode, enable the KV Store sync
searches first: the reconciliation reads the KV Store. A repaired deployment takes the identity the stream
input gives it (table above), so the stream input and the reconciliation never overwrite each other. Before
it exits, the search retries the reports a transient OpenCTI failure left queued, through the same backoff,
for at most 90 seconds; the summary row counts the reports still unsent as `writeback_deferred`, and the
next run plans them again. A deployment Splunk confirmed less than an hour ago (its `last_sync_at` in
OpenCTI) is not withdrawn because `opencti_indicators` lacks it, since in index mode the lookup follows the
index every 5 minutes: the summary row counts it in `count_wait`, and a later run withdraws it if it is
still absent. An empty `opencti_indicators` collection (not synced yet, or being rebuilt)
never withdraws the deployments OpenCTI knows: the search leaves them unchanged and logs a warning. With
`Deployment write-back` disabled, the search reports nothing and returns a `skipped` row.
The search returns a `skipped` row on a platform without the `deployed-on` relationship or without a
deployment write-back mutation.

#### Indicator hits

`OpenCTI - Report indicator hits` (every 15 minutes, over the snapped window `-20m@m` to `-5m@m`, so the
windows never overlap and late events are indexed) matches the indicators against the CIM data models
(`Network_Traffic` source and destination IPs, `Network_Resolution` DNS queries, `Web` URLs,
`Endpoint.Filesystem` and `Endpoint.Processes` hashes, `Email` senders) and pipes one row per indicator
into `| openctireporthits`, which calls `indicatorReportHits` (hit counter of the `deployed-on`
relationship and stable hits sighting Indicator -> Security Platform). On platforms without it, a sighting
on the Security Platform is created instead. Each indicator is reported once per window; replays are
ignored, by the add-on and by OpenCTI. Each data model matches its values against the indicators of the
same kind only (IP addresses, domains and hostnames, URLs, file hashes, email addresses: a file name
indicator never hits on a DNS query), and revoked or expired indicators never hit.

Configure the scope with the `opencti_hits_scope` macro (tstats `where` clause, for example
`index=proxy OR index=firewall`) and set `opencti_hits_summariesonly` to `summariesonly=true` when the data
models are accelerated. Remove an `append` branch of the search to skip a data model. Results also carry
`opencti_hit_status` (`reported`, `reported_as_sighting`, `duplicate`, `invalid`, `error`,
`skipped_no_platform`) and the history is kept in `opencti_indicator_hits`.

The search ends with a heartbeat row (`| append [| makeresults | eval opencti_hits_heartbeat = 1 | fields - _time]`):
when every row of the run was reported, it records the search time range as searched (a contiguous span
per Security Platform, restarted after a failed or skipped run). The IOC validation proof declares a miss
only over a searched span, so keep the heartbeat when you adapt the search.

Two limits of a scheduled search bound what "searched" means, and both are yours to size:
- **Indexing lag**: the window ends 5 minutes before the run, so an event indexed more than 5 minutes after
  its time is never counted, and no later run searches its time again. For slower pipelines, move both
  dispatch times back by the same amount (for example `-35m@m` to `-20m@m`).
- **Subsearch limits**: each data model after the first runs as an `append` subsearch, which Splunk
  finalizes after 60 seconds by default and then returns partial results without telling the command.
  Use accelerated data models (`opencti_hits_summariesonly` = `summariesonly=true`) or narrow
  `opencti_hits_scope` so every branch completes well within that time; a branch cut short still records
  the window as searched.

#### IOC validation proof

OpenCTI asks OpenAEV to run benign tests built from deployed indicators (IOC validation requests).
`OpenCTI - IOC validation proof` (`| openctivalidation`, every 15 minutes) lists the requests that target
the Splunk Security Platform and, for each indicator of the request still waiting for a result on this
platform:

- **detected** when a recorded hit falls in the test window (dispatch to completion of the request,
  give or take 5 minutes of clock skew), or when the last hit OpenCTI recorded on the deployment does.
  Hits carry their event time: the grace period gives the hit reporting time to search the end of the
  test window before a miss is decided; it does not widen the window, nor recover an event indexed after
  the run that searched its time (see the limits above);
- **missed** when the request is completed, the grace period is over, `OpenCTI - Report indicator hits`
  searched the whole test window (see the heartbeat above) and no hit falls in it; a sighting
  with `x_opencti_negative = true` records the miss on the Security Platform;
- **requested** otherwise: no result yet, nothing is written (the `hits_searched_until` column shows how far
  the hit reporting got). This includes a later hit recorded by
  OpenCTI that the local hit history does not hold (lost KV Store write), a hit window running from
  before to after the test (a hit during the test can be neither proven nor ruled out), and a history whose oldest
  windows (beyond the last 50) were trimmed after the test started: a miss is never declared on an
  incomplete history.

Outcomes are written once per request and indicator (`opencti_validation_results`): through
`iocValidationReportResults` when the platform has it, otherwise through a STIX bundle carrying the
`deployed-on` relationship with `validation_status`, `validation_run_id` and `last_validation_at`. Pairs
already resolved by OpenAEV (detected / prevented) are never overwritten. `| openctivalidation
writeback=false` shows the outcomes without writing them.

#### End-to-end proof: OpenAEV benign test -> Splunk event -> hit -> OpenCTI validation status

1. Enable the add-on ingestion (KV Store mode or index mode with the sync searches) and the
   `OpenCTI - Report indicator hits` and `OpenCTI - IOC validation proof` searches.
2. In OpenCTI, request the validation of indicators deployed on the Splunk Security Platform (the
   indicators show the platform in their Deployment tab, written by the add-on). OpenAEV builds a benign
   test per indicator, for example a DNS resolution of a domain indicator from an agent whose DNS logs
   reach Splunk.
3. The test produces a Splunk event, normalized by your technology add-on into the CIM data model
   (`Network_Resolution` for the DNS query).
4. The next run of `OpenCTI - Report indicator hits` matches the event against `opencti_indicators`,
   reports the hit to OpenCTI (hit counter, sighting, deployment status `active`) and records the hit
   window in `opencti_indicator_hits`.
5. `OpenCTI - IOC validation proof` sees the hit inside the test window and writes `detected` for this
   indicator and the Splunk Security Platform. Without a hit, once the request is completed and the grace
   period is over, it writes `missed` and a negative sighting.
6. OpenCTI shows the validation status on the `deployed-on` relationship, in the Security Platform
   Deployments tab and in the dissemination assurance dashboard. In Splunk, the "Dissemination assurance"
   tab of the Monitoring dashboard lists the proofs.

### Custom search commands

| Command                                                       | Type       | Purpose                                                                 |
|---------------------------------------------------------------|------------|-------------------------------------------------------------------------|
| `openctireporthits [id_field] [count_field] [first_field] [last_field]` | eventing (search head) | Report hits per indicator (defaults `indicator_id`, `hit_count`, `first_hit`, `last_hit`) |
| `openctivalidation [writeback=<bool>]`                         | generating | Decide and write back IOC validation outcomes                            |
| `openctireconcile [mode=deployments] [refresh=<bool>]`        | generating | Repair the deployment drift                                              |

The commands run on the search head with the OpenCTI account of the add-on, so the user running them
needs the `list_storage_passwords` capability (the shipped scheduled searches run as the app owner).
They all write to OpenCTI, so none of them runs on search preview results (`run_in_preview = false`): an
interactive search reports once, on its final results. Their logs are in `$SPLUNK_HOME/var/log/splunk/ta-opencti-for-splunk-enterprise_<command>.log`.

### Monitoring

The Monitoring dashboard has a **Dissemination assurance** tab: deployments by status, failed deployments
and last sync, most hit indicators, indicators hit per day, validation statuses and latest validations,
write-back errors.

### Program saved searches (all shipped disabled)

| Saved search                                   | Schedule            | Purpose                                  |
|------------------------------------------------|---------------------|------------------------------------------|
| `OpenCTI - Report indicator hits`              | every 15 minutes    | Indicator hits                           |
| `OpenCTI - IOC validation proof`               | every 15 minutes    | IOC validation outcomes                  |
| `OpenCTI - Reconcile indicator deployments`    | hourly              | Deployment drift repair                  |
