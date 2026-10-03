"""Tests for the Splunk Security Platform identity (WS-A, #68)."""
import unittest

from program_fakes import FakeCache, FakeClient, FakeDetector, FakeLogger, transport_error

from opencti_features import FEATURE_SECURITY_PLATFORM
from security_platform import (
    PlatformSettings,
    SecurityPlatformResolver,
    default_platform_name,
    platform_stix_id,
)

PLATFORM = {"id": "internal-1", "standard_id": "identity--p1", "name": "Splunk sh01", "security_platform_type": "SIEM"}


def _resolver(client, settings, server_name="sh01", cache=None, features=(FEATURE_SECURITY_PLATFORM,), now=None):
    clock = (lambda: now[0]) if now else (lambda: 1000.0)
    return SecurityPlatformResolver(
        client, FakeDetector(features), settings, server_name=server_name, cache=cache, logger=FakeLogger(), clock=clock
    )


def _by_name(nodes):
    return {"securityPlatforms": {"edges": [{"node": node} for node in nodes]}}


class PlatformNameTest(unittest.TestCase):
    def test_default_name_uses_the_server_name(self):
        self.assertEqual(default_platform_name("sh01"), "Splunk sh01")
        self.assertEqual(default_platform_name(""), "Splunk")

    def test_stix_id_matches_the_splunk_saved_searches_importer(self):
        # pycti Identity.generate_id("Splunk", "securityplatform"), used by the importer
        self.assertEqual(platform_stix_id("Splunk"), platform_stix_id(" splunk "))
        self.assertTrue(platform_stix_id("Splunk").startswith("identity--"))

    def test_settings_from_ucc_values(self):
        settings = PlatformSettings.from_mapping({"security_platform_auto_create": "0", "security_platform_name": " SOC "})
        self.assertFalse(settings.auto_create)
        self.assertEqual(settings.name, "SOC")
        self.assertTrue(PlatformSettings.from_mapping({}).auto_create)


class ResolverTest(unittest.TestCase):
    def test_configured_id(self):
        client = FakeClient({"SplunkSecurityPlatform": {"securityPlatform": PLATFORM}})
        self.assertEqual(_resolver(client, PlatformSettings(platform_id="internal-1")).resolve(), PLATFORM)
        self.assertEqual(client.calls_of("SplunkSecurityPlatform"), [{"id": "internal-1"}])

    def test_configured_id_not_found_is_never_auto_created(self):
        client = FakeClient({"SplunkSecurityPlatform": {"securityPlatform": None}})
        self.assertIsNone(_resolver(client, PlatformSettings(platform_id="missing")).resolve())
        self.assertEqual(client.calls_of("SplunkSecurityPlatformAdd"), [])

    def test_auto_resolves_existing_platform_by_name(self):
        client = FakeClient({"SplunkSecurityPlatformByName": _by_name([PLATFORM])})
        self.assertEqual(_resolver(client, PlatformSettings()).resolve(), PLATFORM)
        filters = client.calls_of("SplunkSecurityPlatformByName")[0]["filters"]
        self.assertEqual(filters["filters"][0]["values"], ["Splunk sh01"])

    def test_auto_creates_a_siem_platform(self):
        client = FakeClient({
            "SplunkSecurityPlatformByName": _by_name([]),
            "SplunkSecurityPlatformAdd": {"securityPlatformAdd": PLATFORM},
        })
        self.assertEqual(_resolver(client, PlatformSettings(name="SOC Splunk")).resolve(), PLATFORM)
        created = client.calls_of("SplunkSecurityPlatformAdd")[0]["input"]
        self.assertEqual(created["name"], "SOC Splunk")
        self.assertEqual(created["security_platform_type"], "SIEM")

    def test_creation_upserting_a_platform_of_another_type_is_not_adopted(self):
        edr = dict(PLATFORM, id="internal-edr", security_platform_type="EDR")
        client = FakeClient({
            "SplunkSecurityPlatformByName": _by_name([]),
            "SplunkSecurityPlatformAdd": {"securityPlatformAdd": edr},
        })
        resolver = _resolver(client, PlatformSettings())
        self.assertIsNone(resolver.resolve())
        self.assertTrue(resolver.logger.has("error", "not SIEM"))

    def test_auto_prefers_the_siem_platform_of_that_name(self):
        edr = dict(PLATFORM, id="internal-edr", security_platform_type="EDR")
        client = FakeClient({"SplunkSecurityPlatformByName": _by_name([edr, PLATFORM])})
        self.assertEqual(_resolver(client, PlatformSettings()).resolve(), PLATFORM)

    def test_auto_never_adopts_nor_shadows_a_platform_of_another_type(self):
        edr = dict(PLATFORM, id="internal-edr", security_platform_type="EDR")
        client = FakeClient({"SplunkSecurityPlatformByName": _by_name([edr])})
        resolver = _resolver(client, PlatformSettings())
        self.assertIsNone(resolver.resolve())
        self.assertEqual(client.calls_of("SplunkSecurityPlatformAdd"), [])
        self.assertTrue(resolver.logger.has("error", "not of type SIEM"))

    def test_cached_auto_resolution_of_another_type_is_not_reused(self):
        cache = FakeCache()
        edr = dict(PLATFORM, id="internal-edr", security_platform_type="EDR")
        first = _resolver(FakeClient({"SplunkSecurityPlatformByName": _by_name([PLATFORM])}), PlatformSettings(), cache=cache)
        first.resolve()
        cache.values[first.cache_key]["platform"] = edr
        client = FakeClient({"SplunkSecurityPlatformByName": _by_name([PLATFORM])})
        self.assertEqual(_resolver(client, PlatformSettings(), cache=cache).resolve(), PLATFORM)
        self.assertEqual(len(client.calls_of("SplunkSecurityPlatformByName")), 1)

    def test_cached_auto_resolution_is_dropped_once_auto_mode_is_disabled(self):
        cache = FakeCache()
        _resolver(FakeClient({"SplunkSecurityPlatformByName": _by_name([PLATFORM])}), PlatformSettings(), cache=cache).resolve()
        client = FakeClient({})
        self.assertIsNone(_resolver(client, PlatformSettings(auto_create=False), cache=cache).resolve())
        self.assertEqual(client.calls_of("SplunkSecurityPlatformByName"), [])

    def test_configured_id_of_another_type_is_rejected(self):
        edr = dict(PLATFORM, security_platform_type="EDR")
        client = FakeClient({"SplunkSecurityPlatform": {"securityPlatform": edr}})
        resolver = _resolver(client, PlatformSettings(platform_id="internal-1"))
        self.assertIsNone(resolver.resolve())
        self.assertTrue(resolver.logger.has("error", "not SIEM"))

    def test_auto_creation_disabled(self):
        client = FakeClient()
        self.assertIsNone(_resolver(client, PlatformSettings(auto_create=False)).resolve())
        self.assertEqual(client.calls, [])

    def test_platform_without_security_platforms(self):
        client = FakeClient()
        self.assertIsNone(_resolver(client, PlatformSettings(), features=()).resolve())
        self.assertEqual(client.calls, [])

    def test_auto_resolution_is_shared_by_search_heads_with_other_names(self):
        cache = FakeCache()
        first = FakeClient({"SplunkSecurityPlatformByName": _by_name([PLATFORM])})
        _resolver(first, PlatformSettings(), server_name="sh01", cache=cache).resolve()
        second = FakeClient()
        self.assertEqual(_resolver(second, PlatformSettings(), server_name="sh02", cache=cache).resolve(), PLATFORM)
        self.assertEqual(second.calls, [])

    def test_search_heads_resolving_concurrently_create_one_platform_name(self):
        cache = FakeCache()
        # sh02 resolves before sh01 cached anything: both use the name sh01 recorded first
        first = FakeClient({"SplunkSecurityPlatformByName": _by_name([]),
                            "SplunkSecurityPlatformAdd": {"securityPlatformAdd": PLATFORM}})
        sh01 = _resolver(first, PlatformSettings(), server_name="sh01", cache=cache)
        self.assertEqual(sh01._shared_name(), "Splunk sh01")
        second = FakeClient({"SplunkSecurityPlatformByName": _by_name([]),
                             "SplunkSecurityPlatformAdd": {"securityPlatformAdd": PLATFORM}})
        self.assertEqual(_resolver(second, PlatformSettings(), server_name="sh02", cache=cache).resolve(), PLATFORM)
        self.assertEqual(second.calls_of("SplunkSecurityPlatformByName")[0]["filters"]["filters"][0]["values"],
                         ["Splunk sh01"])
        self.assertEqual(second.calls_of("SplunkSecurityPlatformAdd")[0]["input"]["name"], "Splunk sh01")

    def test_configured_name_and_memory_cache_skip_the_election(self):
        from addon_state import MemoryCache

        client = FakeClient({"SplunkSecurityPlatformByName": _by_name([dict(PLATFORM, name="SOC")])})
        cache = FakeCache()
        self.assertEqual(_resolver(client, PlatformSettings(name="SOC"), cache=cache).resolve()["name"], "SOC")
        self.assertFalse(any(key.startswith("platform-name|") for key in cache.values))
        self.assertEqual(_resolver(client, PlatformSettings(), server_name="sh09", cache=MemoryCache())._shared_name(),
                         "Splunk sh09")

    def test_changing_the_configured_name_invalidates_the_cache(self):
        cache = FakeCache()
        first = FakeClient({"SplunkSecurityPlatformByName": _by_name([PLATFORM])})
        _resolver(first, PlatformSettings(), cache=cache).resolve()
        renamed = dict(PLATFORM, name="SOC", id="internal-2")
        second = FakeClient({"SplunkSecurityPlatformByName": _by_name([renamed])})
        self.assertEqual(_resolver(second, PlatformSettings(name="SOC"), cache=cache).resolve(), renamed)

    def test_stale_auto_resolution_is_reverified_under_its_own_name(self):
        cache = FakeCache()
        now = [1000.0]
        first = FakeClient({"SplunkSecurityPlatformByName": _by_name([PLATFORM])})
        _resolver(first, PlatformSettings(), server_name="sh01", cache=cache, now=now).resolve()
        now[0] += 7200
        second = FakeClient({"SplunkSecurityPlatformByName": _by_name([PLATFORM])})
        _resolver(second, PlatformSettings(), server_name="sh02", cache=cache, now=now).resolve()
        self.assertEqual(second.calls_of("SplunkSecurityPlatformByName")[0]["filters"]["filters"][0]["values"], ["Splunk sh01"])

    def test_transport_error_is_retried_on_next_call(self):
        client = FakeClient({"SplunkSecurityPlatformByName": transport_error()})
        resolver = _resolver(client, PlatformSettings())
        self.assertIsNone(resolver.resolve())
        client.handlers["SplunkSecurityPlatformByName"] = _by_name([PLATFORM])
        self.assertEqual(resolver.resolve(), PLATFORM)

    def test_failed_detection_is_not_a_permanent_absence(self):
        client = FakeClient({"SplunkSecurityPlatformByName": _by_name([PLATFORM])})
        detector = FakeDetector((), failed=True)
        resolver = SecurityPlatformResolver(client, detector, PlatformSettings(), server_name="sh01", logger=FakeLogger())
        self.assertIsNone(resolver.resolve())
        detector.features.add(FEATURE_SECURITY_PLATFORM)
        detector.failed = False
        self.assertEqual(resolver.resolve(), PLATFORM)

    def test_invalidate(self):
        cache = FakeCache()
        client = FakeClient({"SplunkSecurityPlatformByName": _by_name([PLATFORM])})
        resolver = _resolver(client, PlatformSettings(), cache=cache)
        resolver.resolve()
        resolver.invalidate()
        resolver.resolve()
        self.assertEqual(len(client.calls_of("SplunkSecurityPlatformByName")), 2)

    def test_long_running_process_looks_a_missing_platform_up_again(self):
        import security_platform

        now = [1000.0]
        client = FakeClient({"SplunkSecurityPlatform": {"securityPlatform": None}})
        resolver = _resolver(client, PlatformSettings(platform_id="internal-1"), now=now)
        self.assertIsNone(resolver.resolve())
        self.assertIsNone(resolver.resolve(), "a recent negative resolution is reused")
        self.assertEqual(len(client.calls_of("SplunkSecurityPlatform")), 1)
        client.handlers["SplunkSecurityPlatform"] = {"securityPlatform": PLATFORM}
        now[0] += security_platform.NEGATIVE_TTL_SECONDS + 1
        self.assertEqual(resolver.resolve(), PLATFORM)

    def test_long_running_process_verifies_the_platform_again(self):
        import security_platform

        now = [1000.0]
        client = FakeClient({"SplunkSecurityPlatform": {"securityPlatform": PLATFORM}})
        resolver = _resolver(client, PlatformSettings(platform_id="internal-1"), now=now)
        resolver.resolve()
        now[0] += security_platform.CACHE_TTL_SECONDS + 1
        client.handlers["SplunkSecurityPlatform"] = {"securityPlatform": None}
        self.assertIsNone(resolver.resolve(), "a deleted platform is noticed")


if __name__ == "__main__":
    unittest.main()
