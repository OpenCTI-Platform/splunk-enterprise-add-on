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
  Security Platform, carrying `x_opencti_hunt_run_id`, attached to the hunt run when supported. Their
  ids are OpenCTI's standard ids (the same observation is one object linked to each run), and they
  are attached once the OpenCTI workers ingested them; objects still not ingested after 15 seconds
  are attached by the next evidence report of the run, without counting the hits of their report twice.
- Provenance (`corroboration_count`, `last_asserted_at`, `single_sourced`, sources...) and Threat Pulse
  (`pulse_prevalence`, `pulse_trend`, `pulse_first_seen_network`) fields on `opencti_indicators` and
  index events, refreshed daily (`| openctireconcile mode=knowledge`), with filter macros.
- Create Incident / Create Incident Response: timeline milestone (alert name, trigger time, results
  link; lane `detection`, kind `milestone`, external id `splunk:<alert sid>`, authored by the Splunk
  Security Platform, pointing to the alert's indicator when known) and optional Run Case Autopilot
  (Enterprise Edition), once the object is ingested.
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
  lookup searches key it with. The incremental and nightly lookup searches read delete events too:
  the incremental search overwrites a deleted indicator with a revoked tombstone without value or
  pattern (so an entry restored by a concurrent run never stays matchable), and the nightly rebuild
  leaves it out of `opencti_indicators`. A KV Store lookup that fails for another reason than a
  missing entry reports the delete as failed instead of removed.
- The Security Platform must be of type SIEM: a same-name platform of another type is neither adopted
  nor shadowed by a new one, a configured id of another type is rejected, a creation that OpenCTI
  upserted onto a platform of another type is not adopted, and a cached resolution is reused only for
  a SIEM platform while its configuration (auto mode, name) is unchanged.
- Deployment write-back is enabled on platforms exposing only the batched
  `indicatorReportDeployments` mutation; the reconciliation is skipped on a platform exposing neither
  write-back mutation, instead of planning repairs it cannot report.
- IOC validation proves a detection only with a hit inside the test window (the grace period no
  longer widens it), and never declares a miss when a hit window spans the test or the hit history
  was trimmed past its start. A miss also needs proof that `OpenCTI - Report indicator hits` searched
  the whole test window: the search ends with a heartbeat row that records its time range as one
  contiguous span per Security Platform, only when every row of the run was reported.
- `opencti_hits_match` returns one row per matching indicator when several indicators share a value,
  and reads `revoked` per indicator (`opencti_usable_indicator` leaves out an indicator revoked in any
  of its KV Store entries), instead of filtering multivalue fields aligned by position.
- A corrupt feature detection cache entry (undecodable or wrongly typed) triggers a new detection
  instead of failing it.
- The modular input no longer logs the proxy password.
- Hash detections and hit reporting reduce `Filesystem.file_hash` to its digest (CIM values such as
  `sha256=<digest>`), as already done for `Processes.process_hash`.
- Run Case Autopilot reserves the container atomically in the KV Store, so concurrent alert runs
  never start two runs for the same object; a stale reservation is taken over atomically too (one
  takeover key per stale reservation), so two processes never both take it over.
- Report hunt evidence parks each report's not-yet-ingested evidence under its own KV Store entry and
  claims an entry atomically before attaching it, so concurrent reports of one hunt run never lose
  or double-attach deferred evidence. A claim left by a dead process is taken over after ten minutes
  (atomically, once), and without a persistent KV Store the evidence that is not ingested yet is
  reported as not attached instead of being parked in process memory.
- A process that dies while taking over a stale Case Autopilot reservation or hunt evidence claim no
  longer blocks it for good: its takeover entry goes stale in turn and is taken over the same way.
- Timeline milestones and Case Autopilot runs whose incident is not ingested within the 60 second wait,
  or whose call failed, are parked in the KV Store and retried by the next OpenCTI alert action runs
  (24 hours, 5 failed calls at most) instead of being dropped.
- Report hunt evidence fails the result when the evidence cannot be linked to the run (OpenCTI rejects
  the link, or the KV Store is unavailable to defer objects not ingested yet) instead of reporting success;
  a rejected link is parked with its hits and retried by the next report of the run. Objects only waiting
  for ingestion stay a deferral, not a failure.
- The knowledge refresh keeps the platform-wide `assertions_count`, `sources_by_kind` and
  `first_asserted_at` when the account sees only part of the sources (OpenCTI filters assertions per
  user), and `assertions_count` sums `assert_count` like the stream extension; `sources` lists the names
  the account sees.
- `| openctireconcile` (deployments mode) honours a disabled "Deployment write-back" setting: it reports
  nothing and returns a skipped row.
- A deployment created by the reconciliation takes the identity the stream input gives it: the external id
  OpenCTI holds, else the one the stream input reported (`opencti_deployments`), else
  `index:<index>/<indicator id>` for lookup entries built from index events (new `source_index` field),
  else the KV Store entry.
- Search heads of a cluster resolving the Security Platform for the first time at the same moment share
  one default name (the first one recorded in the replicated KV Store), so they upsert one platform
  instead of creating one per member.
- `opencti_multi_sourced_indicator` and `opencti_fresh_indicator` keep nothing when the provenance fields
  are absent, like the other knowledge filters (they used to keep every indicator).
- An Incident or Case-Incident built from a result without `_time` takes the time the alert was
  dispatched (from its search id) instead of the current time, so retries of one triggered alert upsert
  the same object.
- The OpenCTI pattern fallback of Create Sighting also matches the case variants of case-insensitive
  values (domains, IP addresses, emails, hashes), and an unknown one is created in lower case, so an
  uppercase hash from Splunk no longer creates a duplicate indicator.
- One malformed or failing parked follow-up or deferred hunt evidence entry no longer stops the others
  from being retried.
- `| openctivalidation` asks OpenCTI only for the active IOC validation requests of its Security Platform
  (`platform_ids` and `status` filter keys), so requests of other platforms no longer push the Splunk ones
  out of the 5 scanned pages; platforms without these filter keys are scanned and filtered locally as before.
- The `provides` relationship (telemetry inventory) is detected under the `SecurityPlatform_Data-Component`
  key OpenCTI's relationship mapping actually returns, so the inventory is no longer skipped on platforms
  that support it.
- Threat Pulse preview mode: the add-on selects only the `PulseInformation` fields the platform exposes
  (introspected), reads `prevalence_bucket` as well as `prevalence`, stores `pulse_preview`, and the
  Threat Pulse dashboard tab labels preview-based values; the network fields are never assumed.
- Dashboards and the indicator lookup searches read KV Store timestamps at second and millisecond
  precision alike (the 30-day hit chart, the indicators added chart, the last deployment sync, the
  `added_at` of an indicator first written by the KV Store mode).
