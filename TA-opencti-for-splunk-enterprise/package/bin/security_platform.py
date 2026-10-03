"""Identity of this Splunk deployment in OpenCTI: a Security Platform of type SIEM.

Deployments, hits, validation proofs, sightings, hunt evidence and telemetry
(provides) are all attached to this one entity, so OpenCTI can tell what
Splunk holds, what it saw and what it proved. The platform is either the one
configured by id, or resolved / created by name (default "Splunk <server>").
The deterministic STIX id derived from the name is the one the
splunk-saved-searches importer uses, so both integrations converge on the
same entity when they are given the same name.
"""

import logging
import time

from app_connector_helper import OpenCTIGraphQLError
from opencti_features import FEATURE_SECURITY_PLATFORM
from utils import generate_identity_id

SECURITY_PLATFORM_TYPE = "SIEM"
DEFAULT_PLATFORM_PREFIX = "Splunk"
CACHE_TTL_SECONDS = 3600
# A missing platform (not found, not readable, not created) is looked up again after this delay.
NEGATIVE_TTL_SECONDS = 300
# Error OpenCTI returns for a platformId it does not know (indicatorReportDeployment and siblings)
PLATFORM_MISSING_ERROR = "security platform not found"
PLATFORM_FIELDS = "id standard_id name security_platform_type"

PLATFORM_BY_ID_QUERY = """
query SplunkSecurityPlatform($id: String!) {
  securityPlatform(id: $id) { %s }
}
""" % PLATFORM_FIELDS

PLATFORM_BY_NAME_QUERY = """
query SplunkSecurityPlatformByName($filters: FilterGroup) {
  securityPlatforms(first: 5, filters: $filters) { edges { node { %s } } }
}
""" % PLATFORM_FIELDS

PLATFORM_ADD_MUTATION = """
mutation SplunkSecurityPlatformAdd($input: SecurityPlatformAddInput!) {
  securityPlatformAdd(input: $input) { %s }
}
""" % PLATFORM_FIELDS


class PlatformSettings:
    """Security Platform configuration (Configuration > Security Platform tab)."""

    def __init__(self, platform_id="", auto_create=True, name=""):
        self.platform_id = (platform_id or "").strip()
        self.auto_create = bool(auto_create)
        self.name = (name or "").strip()

    @classmethod
    def from_mapping(cls, values):
        values = values or {}
        auto = values.get("security_platform_auto_create")
        return cls(
            platform_id=values.get("security_platform_id", ""),
            auto_create=True if auto in (None, "") else str(auto).strip().lower() in ("1", "true", "yes"),
            name=values.get("security_platform_name", ""),
        )


def default_platform_name(server_name):
    """
    :param server_name: Splunk serverName (server.conf [general])
    :return: "Splunk <server>" or "Splunk" when the server name is unknown
    """
    server_name = (server_name or "").strip()
    return f"{DEFAULT_PLATFORM_PREFIX} {server_name}" if server_name else DEFAULT_PLATFORM_PREFIX


def _is_siem(platform):
    return (platform.get("security_platform_type") or "").upper() == SECURITY_PLATFORM_TYPE


def platform_stix_id(name):
    """
    :return: the deterministic STIX id OpenCTI gives a Security Platform named ``name``
    """
    return generate_identity_id(name, "securityplatform")


class SecurityPlatformResolver:
    def __init__(self, client, detector, settings, server_name="", cache=None, logger=None, clock=time.time):
        """
        :param client: SplunkAppConnectorHelper
        :param detector: OpenCTIFeatureDetector
        :param settings: PlatformSettings
        :param server_name: Splunk server name, used for the default name
        :param cache: optional persistent cache (addon_state.KVStoreCache)
        """
        self.client = client
        self.detector = detector
        self.settings = settings
        self.server_name = server_name
        self.cache = cache
        self.logger = logger or logging.getLogger(__name__)
        self.clock = clock
        self._resolved = None
        self._resolved_at = 0.0

    @property
    def wanted_name(self):
        return self.settings.name or default_platform_name(self.server_name)

    @property
    def cache_key(self):
        # Auto mode is keyed on the URL only: the first resolution is shared
        # by every search head (the KV Store replicates across a cluster), so
        # members with different server names keep one Security Platform.
        target = self.settings.platform_id or "auto"
        return f"platform|{self.client.opencti_url}|{target}"

    def _cache_entry(self):
        if self.cache is None:
            return None
        try:
            entry = self.cache.get(self.cache_key)
        except Exception as ex:
            self.logger.warning(f"Security Platform cache read failed: {ex}")
            return None
        if not isinstance(entry, dict) or not isinstance(entry.get("platform"), dict):
            return None
        if not _is_siem(entry["platform"]):
            return None
        if not self.settings.platform_id:
            # Disabling auto mode or changing the configured name invalidates an auto resolution.
            if not self.settings.auto_create:
                return None
            if (entry.get("configured_name") or "") != self.settings.name:
                return None
        return entry

    def _fresh(self, entry):
        return self.clock() - float(entry.get("resolved_at") or 0) <= CACHE_TTL_SECONDS

    def _to_cache(self, platform):
        if self.cache is None:
            return
        try:
            self.cache.set(self.cache_key, {
                "platform": platform,
                "configured_name": self.settings.name,
                "resolved_at": self.clock(),
            })
        except Exception as ex:
            self.logger.warning(f"Security Platform cache write failed: {ex}")

    def invalidate(self):
        """Forget the resolution (the platform was deleted or became unreadable)."""
        self._resolved = None
        if self.cache is not None:
            try:
                self.cache.set(self.cache_key, {})
            except Exception as ex:
                self.logger.warning(f"Security Platform cache reset failed: {ex}")

    def _find_by_name(self, name):
        """
        :return: (SIEM Security Platform with this name or None, True when only
            platforms of another type carry the name)
        """
        filters = {
            "mode": "and",
            "filters": [{"key": ["name"], "values": [name], "operator": "eq"}],
            "filterGroups": [],
        }
        data = self.client.graphql_query(PLATFORM_BY_NAME_QUERY, {"filters": filters})
        edges = ((data.get("securityPlatforms") or {}).get("edges")) or []
        other_type = False
        for edge in edges:
            node = (edge or {}).get("node") or {}
            if (node.get("name") or "").strip().lower() != name.lower():
                continue
            if _is_siem(node):
                return node, False
            other_type = True
        return None, other_type

    def _create(self, name):
        description = (
            "Splunk Enterprise deployment connected through the OpenCTI for Splunk "
            "Enterprise add-on (indicator deployments, hits, IOC validation proofs, "
            "sightings and telemetry)."
        )
        data = self.client.graphql_query(PLATFORM_ADD_MUTATION, {
            "input": {
                "name": name,
                "description": description,
                "security_platform_type": SECURITY_PLATFORM_TYPE,
            }
        })
        return data.get("securityPlatformAdd")

    def resolve(self):
        """
        :return: dict (id, standard_id, name, security_platform_type) or None
            when the platform has no Security Platform entity or none is configured
        """
        if self._resolved is not None:
            # Long-running processes (the stream input) look the platform up again
            # once the resolution is old, so a deleted or late-created platform is seen.
            ttl = CACHE_TTL_SECONDS if self._resolved else NEGATIVE_TTL_SECONDS
            if self.clock() - self._resolved_at <= ttl:
                return self._resolved or None
            self._resolved = None
        if not self.detector.require(FEATURE_SECURITY_PLATFORM, "Splunk Security Platform resolution"):
            # A failed detection (platform unreachable) is retried later.
            if not self.detector.snapshot().get("failed"):
                self._remember({})
            return None
        entry = self._cache_entry()
        if entry and self._fresh(entry):
            self._remember(entry["platform"])
            return self._resolved
        platform = None
        try:
            if self.settings.platform_id:
                data = self.client.graphql_query(PLATFORM_BY_ID_QUERY, {"id": self.settings.platform_id})
                platform = data.get("securityPlatform")
                if not platform:
                    self.logger.error(
                        f"Security Platform {self.settings.platform_id} not found or not readable by the "
                        "OpenCTI account: platform-aware features are disabled until it is fixed"
                    )
                elif not _is_siem(platform):
                    self.logger.error(
                        f"The configured Security Platform {self.settings.platform_id} is of type "
                        f"{platform.get('security_platform_type')}, not {SECURITY_PLATFORM_TYPE}: "
                        "platform-aware features are disabled until a SIEM platform is configured"
                    )
                    platform = None
            elif self.settings.auto_create:
                # Re-verify a stale auto resolution under its own name.
                name = (entry["platform"].get("name") if entry else None) or self.wanted_name
                platform, other_type = self._find_by_name(name)
                if other_type:
                    self.logger.error(
                        f"The Security Platform '{name}' in OpenCTI is not of type {SECURITY_PLATFORM_TYPE}: "
                        "it is not used for Splunk. Set another Security Platform name or id "
                        "(Configuration > Security Platform)"
                    )
                elif platform is None:
                    platform = self._create(name)
                    if platform:
                        self.logger.info(
                            f"Created the Security Platform '{name}' ({platform.get('id')}) of type "
                            f"{SECURITY_PLATFORM_TYPE} in OpenCTI"
                        )
            else:
                self.logger.info(
                    "No Security Platform configured and auto-creation disabled: platform-aware "
                    "features (deployments, hits, validation, provides) are disabled"
                )
        except OpenCTIGraphQLError as ex:
            self.logger.error(f"Security Platform resolution failed: {ex}")
            return None
        if platform:
            self._to_cache(platform)
            self._remember(platform)
            return platform
        self._remember({})
        return None

    def _remember(self, platform):
        self._resolved = platform
        self._resolved_at = self.clock()
