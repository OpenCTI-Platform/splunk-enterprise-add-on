"""Schema feature detection for the OpenCTI platform the add-on talks to.

Every call the add-on makes beyond the historical STIX bundle push depends on
a platform capability that older OpenCTI releases do not have. The detector
reads the GraphQL schema once (introspection of the root types and of the
Indicator type, plus the relationship mapping), caches the result per
platform and answers ``has(feature)``. Callers skip the call when the feature
is absent and the detector logs it once per process, so the add-on keeps
working - as before - on every OpenCTI version.
"""

import json
import logging
import time

from app_connector_helper import OpenCTIGraphQLError

# Features (stable identifiers, also used in logs and in the README matrix)
FEATURE_SECURITY_PLATFORM = "security_platform"
FEATURE_DEPLOYED_ON = "deployed_on"
FEATURE_DEPLOYMENT = "deployment_writeback"
FEATURE_DEPLOYMENT_BATCH = "deployment_writeback_batch"
FEATURE_HITS = "indicator_hits"
FEATURE_IOC_VALIDATION = "ioc_validation"
FEATURE_IOC_VALIDATION_RESULTS = "ioc_validation_results"
FEATURE_TIMELINE = "timeline"
FEATURE_CASE_AUTOPILOT = "case_autopilot"
FEATURE_HUNTS = "hunts"
FEATURE_HUNT_EVIDENCE = "hunt_evidence"
FEATURE_PROVIDES = "provides"
FEATURE_PROVENANCE = "provenance"
FEATURE_PULSE = "pulse"
FEATURE_ENTERPRISE_EDITION = "enterprise_edition"

# Human readable names used in log lines
FEATURE_LABELS = {
    FEATURE_SECURITY_PLATFORM: "Security Platform entity",
    FEATURE_DEPLOYED_ON: "deployed-on relationship (dissemination assurance)",
    FEATURE_DEPLOYMENT: "indicator deployment write-back (indicatorReportDeployment)",
    FEATURE_DEPLOYMENT_BATCH: "batched deployment write-back (indicatorReportDeployments)",
    FEATURE_HITS: "indicator hit reporting (indicatorReportHits)",
    FEATURE_IOC_VALIDATION: "IOC validation requests (iocValidationRequests)",
    FEATURE_IOC_VALIDATION_RESULTS: "SIEM validation results (iocValidationReportResults)",
    FEATURE_TIMELINE: "incident and case timeline (timelineEventAdd)",
    FEATURE_CASE_AUTOPILOT: "Case Autopilot (investigationRunAdd, Enterprise Edition)",
    FEATURE_HUNTS: "hunt runs (huntRun)",
    FEATURE_HUNT_EVIDENCE: "hunt evidence write-back (huntRunEvidenceAdd)",
    FEATURE_PROVIDES: "provides relationship (defense matrix telemetry)",
    FEATURE_PROVENANCE: "provenance and corroboration fields",
    FEATURE_PULSE: "Threat Pulse fields",
    FEATURE_ENTERPRISE_EDITION: "Enterprise Edition license",
}

DEFAULT_TTL_SECONDS = 3600
# A failed detection is retried sooner than a successful one is refreshed.
FAILURE_TTL_SECONDS = 60

INTROSPECTION_QUERY = """
query OpenCTIFeatureDetection {
  mutationType: __type(name: "Mutation") { fields { name } }
  queryType: __type(name: "Query") { fields { name } }
  indicatorType: __type(name: "Indicator") { fields { name } }
  pulseType: __type(name: "PulseInformation") { fields { name } }
}
"""

RELATIONS_MAPPING_QUERY = """
query OpenCTIRelationsMapping {
  schemaRelationsTypesMapping { key values }
}
"""

VERSION_QUERY = """
query OpenCTIVersion {
  about { version }
}
"""

ENTERPRISE_EDITION_QUERY = """
query OpenCTIEnterpriseEdition {
  settings { platform_enterprise_edition { license_validated } }
}
"""


def _field_names(type_node):
    if not isinstance(type_node, dict):
        return set()
    return {field.get("name") for field in (type_node.get("fields") or []) if isinstance(field, dict)}


def compute_features(mutations, queries, indicator_fields, relations, enterprise):
    """
    Derive the feature set from the schema facts (pure, unit tested).

    :param mutations: names of the Mutation fields
    :param queries: names of the Query fields
    :param indicator_fields: names of the Indicator fields
    :param relations: dict "FromType_ToType" -> list of relationship types
    :param enterprise: True when the platform has a validated EE license
    :return: sorted list of feature identifiers
    """
    relations = relations or {}
    features = set()
    if "securityPlatformAdd" in mutations and "securityPlatforms" in queries:
        features.add(FEATURE_SECURITY_PLATFORM)
    if "deployed-on" in (relations.get("Indicator_SecurityPlatform") or []) or any(
        name in mutations for name in ("indicatorReportDeployment", "indicatorReportDeployments")
    ):
        features.add(FEATURE_DEPLOYED_ON)
    if "indicatorReportDeployment" in mutations:
        features.add(FEATURE_DEPLOYMENT)
    if "indicatorReportDeployments" in mutations:
        features.add(FEATURE_DEPLOYMENT_BATCH)
    if "indicatorReportHits" in mutations:
        features.add(FEATURE_HITS)
    if "iocValidationRequests" in queries:
        features.add(FEATURE_IOC_VALIDATION)
    if "iocValidationReportResults" in mutations:
        features.add(FEATURE_IOC_VALIDATION_RESULTS)
    if "timelineEventAdd" in mutations:
        features.add(FEATURE_TIMELINE)
    if enterprise:
        features.add(FEATURE_ENTERPRISE_EDITION)
    if "investigationRunAdd" in mutations and enterprise:
        features.add(FEATURE_CASE_AUTOPILOT)
    if "huntRun" in queries:
        features.add(FEATURE_HUNTS)
    if "huntRunEvidenceAdd" in mutations:
        features.add(FEATURE_HUNT_EVIDENCE)
    # Keys are "<from entity type>_<to entity type>": Data Components are "Data-Component"
    if "provides" in (relations.get("SecurityPlatform_Data-Component") or []):
        features.add(FEATURE_PROVIDES)
    if "corroboration_count" in indicator_fields:
        features.add(FEATURE_PROVENANCE)
    if "pulse" in indicator_fields:
        features.add(FEATURE_PULSE)
    return sorted(features)


class OpenCTIFeatureDetector:
    """Cached feature detection for one OpenCTI platform.

    The cache is two-level: in memory for the process, and optionally in a
    persistent store (see addon_state.KVStoreCache) shared by the modular
    input, the alert actions and the search commands, which are separate
    short-lived processes.
    """

    # In-process cache shared by every detector of the process, keyed by URL.
    _memory = {}

    def __init__(self, client, logger=None, cache=None, ttl=DEFAULT_TTL_SECONDS, clock=time.time):
        """
        :param client: SplunkAppConnectorHelper (or any object with
            graphql_query and opencti_url)
        :param logger: logging.Logger-like object
        :param cache: optional persistent cache with get(key) -> dict|None
            and set(key, dict)
        :param ttl: seconds a detection stays valid
        :param clock: time source (tests)
        """
        self.client = client
        self.logger = logger or logging.getLogger(__name__)
        self.cache = cache
        self.ttl = int(ttl) if ttl else DEFAULT_TTL_SECONDS
        self.clock = clock
        self._announced = set()

    @property
    def cache_key(self):
        return "features|" + (getattr(self.client, "opencti_url", "") or "")

    def _fresh(self, entry):
        if not isinstance(entry, dict) or not isinstance(entry.get("features"), list):
            return False
        try:
            ttl = float(entry.get("ttl") or self.ttl)
            return self.clock() - float(entry.get("detected_at") or 0) < ttl
        except (TypeError, ValueError):
            return False

    def _load_cached(self):
        entry = OpenCTIFeatureDetector._memory.get(self.cache_key)
        if self._fresh(entry):
            return entry
        if self.cache is not None:
            try:
                entry = self.cache.get(self.cache_key)
            except Exception as ex:  # a broken cache must never break detection
                self.logger.warning(f"OpenCTI feature cache read failed: {ex}")
                entry = None
            if isinstance(entry, dict) and isinstance(entry.get("features"), str):
                try:
                    entry = dict(entry, features=json.loads(entry["features"]))
                except ValueError:
                    self.logger.warning("OpenCTI feature cache entry is corrupt: detecting again")
                    entry = None
            if self._fresh(entry):
                OpenCTIFeatureDetector._memory[self.cache_key] = entry
                return entry
        return None

    def _store(self, entry):
        OpenCTIFeatureDetector._memory[self.cache_key] = entry
        if self.cache is not None and not entry.get("failed"):
            try:
                self.cache.set(self.cache_key, dict(entry, features=json.dumps(entry["features"])))
            except Exception as ex:
                self.logger.warning(f"OpenCTI feature cache write failed: {ex}")

    def _detect(self):
        data = self.client.graphql_query(INTROSPECTION_QUERY)
        mutations = _field_names(data.get("mutationType"))
        queries = _field_names(data.get("queryType"))
        indicator_fields = _field_names(data.get("indicatorType"))
        relations = {}
        # A transport failure of a secondary query leaves features out: retry
        # it soon rather than caching the reduced set for the whole TTL
        transient = False
        if "schemaRelationsTypesMapping" in queries:
            try:
                mapping = self.client.graphql_query(RELATIONS_MAPPING_QUERY)
                for entry in mapping.get("schemaRelationsTypesMapping") or []:
                    relations[entry.get("key")] = entry.get("values") or []
            except OpenCTIGraphQLError as ex:
                self.logger.warning(f"OpenCTI relationship mapping unavailable: {ex}")
                transient = transient or not ex.errors
        version = "unknown"
        enterprise = False
        try:
            info = self.client.graphql_query(VERSION_QUERY)
            version = ((info.get("about") or {}).get("version")) or "unknown"
        except OpenCTIGraphQLError as ex:
            self.logger.info(f"OpenCTI version not readable with this account: {ex}")
        try:
            info = self.client.graphql_query(ENTERPRISE_EDITION_QUERY)
            ee = (info.get("settings") or {}).get("platform_enterprise_edition") or {}
            enterprise = bool(ee.get("license_validated"))
        except OpenCTIGraphQLError as ex:
            self.logger.info(f"OpenCTI Enterprise Edition status not readable with this account: {ex}")
            transient = transient or not ex.errors
        features = compute_features(mutations, queries, indicator_fields, relations, enterprise)
        return {
            "features": features,
            "version": version,
            "detected_at": self.clock(),
            "ttl": FAILURE_TTL_SECONDS if transient else self.ttl,
            # Threat Pulse fields differ between the preview and full modes
            "pulse_fields": sorted(_field_names(data.get("pulseType"))),
        }

    def snapshot(self, refresh=False):
        """
        :param refresh: ignore the caches
        :return: dict with "features" (list), "version" and "detected_at"
        """
        entry = None if refresh else self._load_cached()
        if entry is not None:
            return entry
        try:
            entry = self._detect()
            self.logger.info(
                f"OpenCTI {entry['version']} at {self.client.opencti_url}: "
                f"features available: {', '.join(entry['features']) or 'none'}"
            )
        except OpenCTIGraphQLError as ex:
            self.logger.warning(
                f"OpenCTI feature detection failed, program features are disabled "
                f"for {FAILURE_TTL_SECONDS}s: {ex}"
            )
            entry = {
                "features": [],
                "version": "unknown",
                "detected_at": self.clock(),
                "ttl": FAILURE_TTL_SECONDS,
                "failed": True,
            }
        self._store(entry)
        return entry

    @property
    def version(self):
        return self.snapshot().get("version", "unknown")

    def has(self, feature):
        """
        :param feature: one of the FEATURE_* identifiers
        :return: True when the platform supports it
        """
        return feature in (self.snapshot().get("features") or [])

    def pulse_fields(self):
        """
        :return: set of the PulseInformation field names, or None when the
            detection predates their introspection (cache of an older add-on)
        """
        fields = self.snapshot().get("pulse_fields")
        if isinstance(fields, str):
            try:
                fields = json.loads(fields)
            except ValueError:
                return None
        return set(fields) if isinstance(fields, list) else None

    def require(self, feature, action):
        """
        Same as has(), and log once per process why ``action`` is skipped.

        :param feature: one of the FEATURE_* identifiers
        :param action: what the caller wanted to do (for the log line)
        :return: True when the platform supports the feature
        """
        if self.has(feature):
            return True
        key = (feature, action)
        if key not in self._announced:
            self._announced.add(key)
            self.logger.info(
                f"{action}: skipped, the OpenCTI platform ({self.version}) does not provide "
                f"the {FEATURE_LABELS.get(feature, feature)}"
            )
        return False

    @classmethod
    def clear_memory(cls):
        cls._memory.clear()
