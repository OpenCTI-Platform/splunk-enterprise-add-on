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
- Defense matrix: ATT&CK-annotated detection searches match the OpenCTI indicators against CIM data, and
  the add-on declares which telemetry Splunk holds, as `provides` relationships of a named Splunk Security
  Platform. See [OpenCTI program compatibility](#opencti-program-compatibility).
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
telemetry the add-on declares to the defense matrix is attached to it. Configure it on the
"Security Platform" tab of the Configuration page:

| Parameter                                | Description                                                                                                                                  | Default            |
|------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|--------------------|
| `Security Platform ID`                   | Id (internal or STIX) of an existing OpenCTI Security Platform. Takes precedence over the name                                               | empty              |
| `Create the Security Platform`           | When no id is set, find the Security Platform by name, or create it (type SIEM)                                                               | enabled            |
| `Security Platform name`                 | Name used to find or create it. Use the same name as the `platform_name` of the OpenCTI `splunk-saved-searches` connector (see below)        | `Splunk <server>`  |
| `Feature detection cache (minutes)`      | How long the capabilities read from the OpenCTI GraphQL schema are cached                                                                     | 60                 |

The resolved Security Platform is cached in the KV Store (`opencti_addon_state`) and shared by every
search head of a cluster, so members with different server names keep one Security Platform. Without a
configured name, the first default name recorded in that collection is used by every member, so members
resolving it for the first time at the same moment create one platform, not one each.

**OpenCTI account permissions.** The account of the add-on needs the capabilities of a connector service
account (bundle push and connector registration) plus "Knowledge: create / update" for the provides
relationships and the Security Platform creation.

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

The add-on feeds the defense matrix of OpenCTI: its detection searches declare the ATT&CK techniques they
cover, and the Splunk telemetry is declared as data components the named Splunk Security Platform provides.

### Compatibility matrix

The add-on reads the OpenCTI GraphQL schema once per platform (cached in the KV Store, see
`Feature detection cache`) and enables each capability only where the platform provides it. Missing
capabilities are skipped with one log line such as
`Telemetry provides declaration: skipped, the OpenCTI platform (<version>) does not provide the provides relationship (defense matrix telemetry)`.

| Add-on capability                                            | OpenCTI capability (detected)                                    | OpenCTI releases without it          |
|--------------------------------------------------------------|------------------------------------------------------------------|--------------------------------------|
| Ingestion, enrichment, Create Incident / Case / Sighting     | live streams, `stixBundlePush`                                   | always available                     |
| ATT&CK-annotated detection searches                          | none (Splunk alerts)                                              | always available                     |
| Splunk Security Platform (configured or auto-created)        | `securityPlatformAdd`, `securityPlatforms`                       | telemetry inventory skipped          |
| Telemetry inventory (`provides`)                             | `provides` relationship (Security Platform -> Data Component)    | skipped                              |

The `openctiprovides` custom search command declares `python.required = 3.13`, the Python runtime of Splunk
Enterprise 10: the libraries the add-on ships (stix2 3.0.2) need Python 3.10 or later, so the Python 3.9
runtime is not supported.

### Detection searches and the defense matrix

#### ATT&CK-annotated detections

The add-on ships detections matching the OpenCTI indicators against CIM data, disabled by default:

| Saved search                                            | Data                                        | MITRE ATT&CK                     |
|---------------------------------------------------------|---------------------------------------------|----------------------------------|
| `OpenCTI - Network traffic with an indicator IP`        | `Network_Traffic` source / destination IP   | T1071, T1095, T1571              |
| `OpenCTI - DNS resolution of an indicator domain`       | `Network_Resolution` DNS query              | T1071.004, T1568                 |
| `OpenCTI - Web request to an indicator URL`             | `Web` URL                                   | T1071.001, T1189, T1566.002      |
| `OpenCTI - File or process matching an indicator hash`  | `Endpoint` file and process hashes          | T1204.002, T1105                 |
| `OpenCTI - Email from an indicator sender`              | `Email` sender                              | T1566.001, T1566.002             |

Each one is a scheduled alert (tracked, throttled per indicator for one hour) whose rows carry
`indicator_id`, `value`, `count`, `first_seen` and `last_seen`. Each one matches its values against the
indicators of the same kind only (IP addresses, domains and hostnames, URLs, file hashes, email
addresses), and revoked or expired indicators never match. A URL matches only the indicator of that
exact URL: the scheme and host in any case, the path, query and fragment exactly. The techniques are
declared in `action.correlationsearch.annotations` (`{"mitre_attack": [...]}`), the convention read by
Splunk Enterprise Security and by the OpenCTI `splunk-saved-searches` connector, which imports them as
detection rules indicating the techniques and deployed on the Splunk Security Platform. Maintenance
searches (KV Store sync, telemetry inventory) declare no technique and trigger no alert action, so the
connector does not import them with its default `alerts` scope.

To make the connector and the add-on target the same Security Platform, set the connector `platform_id`
(`SPLUNK_SAVED_SEARCHES_PLATFORM_ID`) to the id of the add-on Security Platform: the connector then references
that platform and never rewrites it. Without it, set the connector `platform_name` to the add-on Security
Platform name and keep its `platform_type` at `SIEM` (both derive the same identity from name and type).

#### Telemetry inventory (provides)

`OpenCTI - Telemetry inventory` (daily) lists the CIM data models and the sourcetypes holding data over
the last 7 days (`tstats`, so the event counts cover those 7 days only), maps them to MITRE Data Components through the
`opencti_cim_data_components` lookup and pipes one row per data component into `| openctiprovides`, which
declares `provides` relationships Splunk Security Platform -> Data Component in OpenCTI. The defense
matrix then knows which techniques Splunk has telemetry for.

The lookup (`lookups/opencti_cim_data_components.csv`) is editable: one row per `source`
(`datamodel:<Model>[.<Dataset>]` or `sourcetype:<sourcetype>`, wildcards allowed) and `data_component`
(the MITRE Data Component name, as imported in OpenCTI). Data components unknown to OpenCTI are reported
with the status `unmatched_data_component`, and a failed declaration with the status `error`, like every
data component of a run whose Data Component lookup in OpenCTI failed; they are kept in `opencti_provides`
with their message, so the dashboard shows them. A data component that holds provides
relationships in OpenCTI (declared by an earlier run, or partly by this one before the failure) stays
`declared` with all of them, the failure in its message, so pruning can still delete them.
`| openctiprovides prune=true` also deletes the provides relationships the add-on declared earlier for data
components absent from the inventory (and retires their unmatched or failed entries); nothing is
pruned when the inventory is empty or when a declaration of the run failed. With the
default `opencti_inventory_summariesonly` (`summariesonly=true`), only accelerated data models count.

### Custom search commands

| Command                                                       | Type       | Purpose                                                                 |
|---------------------------------------------------------------|------------|-------------------------------------------------------------------------|
| `openctiprovides [prune=<bool>]`                               | eventing (search head) | Declare telemetry as provides relationships                 |

The command runs on the search head with the OpenCTI account of the add-on, so the user running it
needs the `list_storage_passwords` capability (the shipped scheduled search runs as the app owner).
It writes to OpenCTI, so it never runs on search preview results (`run_in_preview = false`): an
interactive search reports once, on its final results. Its logs are in `$SPLUNK_HOME/var/log/splunk/ta-opencti-for-splunk-enterprise_openctiprovides.log`.

### Monitoring

The Monitoring dashboard has a **Defense matrix** tab: data components declared to OpenCTI (provides) and
the telemetry inventory, with the status and message of each data component. Both read the
`opencti_provides_current` macro, the entries of the Security Platform the latest inventory run reported to:
after a change of Security Platform, the entries of the previous one stay in `opencti_provides` (pruning
needs their relationships if it is configured again) but are not counted as current.

### Program saved searches (all shipped disabled)

| Saved search                                   | Schedule            | Purpose                                  |
|------------------------------------------------|---------------------|------------------------------------------|
| `OpenCTI - Network traffic with an indicator IP`, `OpenCTI - DNS resolution of an indicator domain`, `OpenCTI - Web request to an indicator URL`, `OpenCTI - File or process matching an indicator hash`, `OpenCTI - Email from an indicator sender` | every 15 minutes | ATT&CK-annotated detections (alerts) |
| `OpenCTI - Telemetry inventory`                | daily               | Defense matrix telemetry (provides)      |
