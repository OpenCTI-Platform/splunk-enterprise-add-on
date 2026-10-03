# Changelog

All notable changes to the OpenCTI for Splunk Enterprise add-on are documented here.
Every program feature is detected from the OpenCTI GraphQL schema: on an OpenCTI
release without it, the add-on behaves exactly as 1.1.x and logs why a feature is skipped.

## 1.2.0

Compatibility with the OpenCTI autonomous threat management program
(OpenCTI-Platform/splunk-enterprise-add-on#68): "Splunk proves what OpenCTI disseminates".

### Added

- Splunk Security Platform identity: a new Configuration > Security Platform tab selects the
  OpenCTI Security Platform (type SIEM) representing this Splunk deployment, or finds / creates it
  by name (default `Splunk <server name>`). The resolution is cached in the KV Store and shared by
  every search head of a cluster.
- Schema feature detection (`OpenCTIFeatureDetector`): one cached introspection per platform gates
  every new call; absent features are logged once and skipped.
- Indicator deployment write-back: the modular input reports `deployed`, `removed`, `expired` and
  `failed` per indicator (`indicatorReportDeployment(s)`, external id = KV key, or index and indicator STIX id),
  batched, deduplicated, rate limited and retried with backoff; local state in `opencti_deployments`.
- `OpenCTI - Reconcile indicator deployments` (`| openctireconcile`): repairs the drift between the
  `opencti_indicators` KV Store and the `deployed-on` relationships of the Splunk Security Platform.
- Indicator hits: `OpenCTI - Report indicator hits` matches the indicators against CIM data over
  non-overlapping windows and reports them (`| openctireporthits`, `indicatorReportHits`, or a sighting
  on the Security Platform on older platforms); history in `opencti_indicator_hits`.
- IOC validation proof: `OpenCTI - IOC validation proof` (`| openctivalidation`) decides, from the
  reported hits, whether the OpenAEV benign tests of the validation requests targeting Splunk were
  detected or missed, and writes the outcome back (negative sighting for a miss).
- Detection searches matching OpenCTI indicators against CIM data (network traffic, DNS, web, file and
  process hashes, email), annotated with MITRE ATT&CK techniques for Enterprise Security and the
  OpenCTI `splunk-saved-searches` importer.
- Defense matrix telemetry: `OpenCTI - Telemetry inventory` maps the CIM data models and sourcetypes
  holding data to MITRE Data Components through the editable `opencti_cim_data_components` lookup and
  declares them as `provides` relationships (`| openctiprovides`).
- Alert action `OpenCTI - Report hunt evidence`: Observed-Data and sightings of the hunt targets on the
  Security Platform, carrying `x_opencti_hunt_run_id`, attached to the hunt run when supported.
- Provenance (`corroboration_count`, `last_asserted_at`, `single_sourced`, sources...) and Threat Pulse
  (`pulse_prevalence`, `pulse_trend`, `pulse_first_seen_network`) fields on `opencti_indicators` and
  index events, refreshed daily (`| openctireconcile mode=knowledge`), with filter macros.
- Create Incident / Create Incident Response: timeline milestone (alert name, trigger time, results
  link, lane `custom`) and optional Run Case Autopilot (Enterprise Edition), once the object is ingested.
- Monitoring dashboard tabs: Dissemination assurance, Sources, Threat Pulse, Defense matrix, Hunts, Timeline.
- `opencti_hunt_scope` macro and guidance for the OpenCTI `internal-hunt/splunk` connector.

### Changed

- Create Sighting: new "Indicator ID" and "<type> Indicator" types sight OpenCTI indicators
  (STIX 2.1 compliant, #57, #67); sightings are made on the Splunk Security Platform, the
  "Where Sighted" System / Organization becoming optional; new Count parameter.
- Create Sighting: the default type is now "Domain Indicator". The legacy "<type> Observable" types
  sight the matching indicator instead of a placeholder indicator, which OpenCTI rejects (#57). The
  observable is still sent, linked by `based-on`. Their sightings get indicator-based ids, so the
  first run after the upgrade creates new sightings instead of updating the 1.1.x ones.
- Create Incident / Create Incident Response: optional Incident key parameter (result field names read
  on every result, for example `user,src`); indexed events fold
  their identity into the object id so distinct same-second results never merge (#47). Rows of
  transforming searches without a key that share a name and second in one run get distinct ids.
- Upgrade note: an indexed event already sent by 1.1.x gets a new Incident / Case-Incident id in
  1.2.0, so an event returned again by an overlapping scheduled run right after the upgrade creates a
  second object once. Rows of transforming searches keep their 1.1.x id (the first row of each name
  and second).

### Fixed

- Alert actions return a non-zero exit code when a result fails, so Splunk reports the failure (#18).
- `register()` and `send_stix_bundle()` check GraphQL errors returned with HTTP 200 (#19); the
  connector registers once per alert run; every OpenCTI call has a timeout.
- Index mode: delete events purge the KV Store entry by its `_key` (#20), and by the STIX id the
  lookup searches key it with. The incremental and nightly lookup searches read delete events too,
  so a deleted indicator is never written back to `opencti_indicators`.
- The Security Platform found by name must be of type SIEM; a same-name platform of another type is
  neither adopted nor shadowed by a new one.
- The modular input no longer logs the proxy password.
- Hash detections and hit reporting reduce `Filesystem.file_hash` to its digest (CIM values such as
  `sha256=<digest>`), as already done for `Processes.process_hash`.
- Run Case Autopilot reserves the container atomically in the KV Store, so concurrent alert runs
  never start two runs for the same object.
