"""Tests for OpenCTIFeatureDetector (schema feature detection, #68)."""
import unittest

from program_fakes import FakeCache, FakeClient, FakeLogger, graphql_error, transport_error

import opencti_features as features
from opencti_features import OpenCTIFeatureDetector, compute_features


def _schema(mutations=(), queries=(), indicator=()):
    return {
        "mutationType": {"fields": [{"name": n} for n in mutations]},
        "queryType": {"fields": [{"name": n} for n in queries]},
        "indicatorType": {"fields": [{"name": n} for n in indicator]},
    }


PROGRAM_MUTATIONS = (
    "securityPlatformAdd", "indicatorReportDeployment", "indicatorReportDeployments", "indicatorReportHits",
    "timelineEventAdd", "investigationRunAdd", "huntRunEvidenceAdd", "iocValidationReportResults",
)
PROGRAM_QUERIES = ("securityPlatforms", "iocValidationRequests", "huntRun", "schemaRelationsTypesMapping", "about")


def _client(schema, relations=None, version="7.261003.0", enterprise=True, fail=False):
    def introspection(_):
        return transport_error() if fail else schema

    return FakeClient({
        "OpenCTIFeatureDetection": introspection,
        "OpenCTIRelationsMapping": {"schemaRelationsTypesMapping": [
            {"key": key, "values": values} for key, values in (relations or {}).items()
        ]},
        "OpenCTIVersion": {"about": {"version": version}},
        "OpenCTIEnterpriseEdition": {"settings": {"platform_enterprise_edition": {"license_validated": enterprise}}},
    })


class ComputeFeaturesTest(unittest.TestCase):
    def test_current_release_has_no_program_feature(self):
        result = compute_features({"stixBundlePush", "registerConnector"}, {"indicator"}, {"pattern"}, {}, False)
        self.assertEqual(result, [])

    def test_security_platform_needs_add_and_list(self):
        self.assertIn(features.FEATURE_SECURITY_PLATFORM,
                      compute_features({"securityPlatformAdd"}, {"securityPlatforms"}, set(), {}, False))
        self.assertNotIn(features.FEATURE_SECURITY_PLATFORM,
                         compute_features({"securityPlatformAdd"}, set(), set(), {}, False))

    def test_program_branches_enable_every_feature(self):
        result = compute_features(
            set(PROGRAM_MUTATIONS), set(PROGRAM_QUERIES), {"corroboration_count", "pulse"},
            {"SecurityPlatform_DataComponent": ["provides"], "Indicator_SecurityPlatform": ["deployed-on"]}, True,
        )
        for feature in (
            features.FEATURE_SECURITY_PLATFORM, features.FEATURE_DEPLOYED_ON, features.FEATURE_DEPLOYMENT,
            features.FEATURE_DEPLOYMENT_BATCH, features.FEATURE_HITS, features.FEATURE_IOC_VALIDATION,
            features.FEATURE_IOC_VALIDATION_RESULTS, features.FEATURE_TIMELINE, features.FEATURE_CASE_AUTOPILOT,
            features.FEATURE_HUNTS, features.FEATURE_HUNT_EVIDENCE, features.FEATURE_PROVIDES,
            features.FEATURE_PROVENANCE, features.FEATURE_PULSE, features.FEATURE_ENTERPRISE_EDITION,
        ):
            self.assertIn(feature, result)

    def test_batch_deployment_mutation_alone_means_deployed_on(self):
        result = compute_features({"indicatorReportDeployments"}, set(), set(), {}, False)
        self.assertIn(features.FEATURE_DEPLOYED_ON, result)
        self.assertIn(features.FEATURE_DEPLOYMENT_BATCH, result)
        self.assertNotIn(features.FEATURE_DEPLOYMENT, result)

    def test_case_autopilot_requires_enterprise_edition(self):
        self.assertNotIn(features.FEATURE_CASE_AUTOPILOT,
                         compute_features({"investigationRunAdd"}, set(), set(), {}, False))

    def test_provides_comes_from_the_relationship_mapping(self):
        self.assertNotIn(features.FEATURE_PROVIDES, compute_features(set(), set(), set(), {}, False))
        self.assertIn(features.FEATURE_PROVIDES, compute_features(
            set(), set(), set(), {"SecurityPlatform_DataComponent": ["provides"]}, False))


class DetectorTest(unittest.TestCase):
    def setUp(self):
        OpenCTIFeatureDetector.clear_memory()
        self.now = [1000.0]

    def _detector(self, client, cache=None, ttl=3600, logger=None):
        return OpenCTIFeatureDetector(client, logger=logger or FakeLogger(), cache=cache, ttl=ttl, clock=lambda: self.now[0])

    def test_detects_and_caches_in_memory(self):
        client = _client(_schema(PROGRAM_MUTATIONS, PROGRAM_QUERIES, ("pulse",)))
        detector = self._detector(client)
        self.assertTrue(detector.has(features.FEATURE_HITS))
        self.assertTrue(detector.has(features.FEATURE_PULSE))
        self.assertEqual(detector.version, "7.261003.0")
        detector.has(features.FEATURE_TIMELINE)
        self.assertEqual(len(client.calls_of("OpenCTIFeatureDetection")), 1)

    def test_persistent_cache_is_shared_between_processes(self):
        cache = FakeCache()
        first = _client(_schema(("indicatorReportHits",)))
        self._detector(first, cache=cache).snapshot()
        OpenCTIFeatureDetector.clear_memory()  # new process
        second = _client(_schema())
        self.assertTrue(self._detector(second, cache=cache).has(features.FEATURE_HITS))
        self.assertEqual(second.calls, [])

    def test_corrupt_persistent_entries_are_detected_again(self):
        for corrupt in (
            {"features": "not json", "detected_at": 1000.0},
            {"features": '{"hits": true}', "detected_at": 1000.0},
            {"features": "[]", "detected_at": "yesterday"},
            {"features": "[]", "detected_at": 1000.0, "ttl": "soon"},
        ):
            with self.subTest(corrupt=corrupt):
                OpenCTIFeatureDetector.clear_memory()
                client = _client(_schema(("indicatorReportHits",)))
                cache = FakeCache()
                detector = self._detector(client, cache=cache)
                cache.set(detector.cache_key, corrupt)
                self.assertTrue(detector.has(features.FEATURE_HITS))
                self.assertEqual(len(client.calls_of("OpenCTIFeatureDetection")), 1)

    def test_cache_expires_after_ttl(self):
        client = _client(_schema(("indicatorReportHits",)))
        detector = self._detector(client, ttl=60)
        detector.snapshot()
        self.now[0] += 61
        detector.snapshot()
        self.assertEqual(len(client.calls_of("OpenCTIFeatureDetection")), 2)

    def test_failure_disables_features_and_retries_soon(self):
        cache = FakeCache()
        client = _client(_schema(PROGRAM_MUTATIONS), fail=True)
        logger = FakeLogger()
        detector = self._detector(client, cache=cache, logger=logger)
        self.assertFalse(detector.has(features.FEATURE_HITS))
        self.assertTrue(detector.snapshot().get("failed"))
        self.assertTrue(logger.has("warning", "feature detection failed"))
        self.assertEqual(cache.values, {}, "a failed detection is never persisted")
        self.now[0] += features.FAILURE_TTL_SECONDS + 1
        detector.snapshot()
        self.assertEqual(len(client.calls_of("OpenCTIFeatureDetection")), 2)

    def test_require_logs_once_per_action(self):
        logger = FakeLogger()
        detector = self._detector(_client(_schema()), logger=logger)
        self.assertFalse(detector.require(features.FEATURE_TIMELINE, "Timeline milestone"))
        self.assertFalse(detector.require(features.FEATURE_TIMELINE, "Timeline milestone"))
        skipped = [line for level, line in logger.lines if "Timeline milestone: skipped" in line]
        self.assertEqual(len(skipped), 1)
        self.assertIn("incident and case timeline", skipped[0])

    def test_version_and_license_errors_do_not_break_detection(self):
        client = _client(_schema(("timelineEventAdd",)))
        client.handlers["OpenCTIVersion"] = transport_error("forbidden")
        client.handlers["OpenCTIEnterpriseEdition"] = transport_error("forbidden")
        detector = self._detector(client)
        self.assertTrue(detector.has(features.FEATURE_TIMELINE))
        self.assertEqual(detector.version, "unknown")
        self.assertFalse(detector.has(features.FEATURE_ENTERPRISE_EDITION))

    def test_transient_secondary_failure_is_retried_soon(self):
        schema = _schema(PROGRAM_MUTATIONS, PROGRAM_QUERIES)
        for handler in ("OpenCTIRelationsMapping", "OpenCTIEnterpriseEdition"):
            with self.subTest(handler=handler):
                OpenCTIFeatureDetector.clear_memory()
                client = _client(schema)
                client.handlers[handler] = transport_error()
                detector = self._detector(client)
                self.assertEqual(detector.snapshot()["ttl"], features.FAILURE_TTL_SECONDS)
                self.now[0] += features.FAILURE_TTL_SECONDS + 1
                client.handlers.update(_client(schema).handlers)
                self.assertTrue(detector.has(features.FEATURE_CASE_AUTOPILOT))
                self.assertEqual(detector.snapshot()["ttl"], 3600)

    def test_permission_error_on_the_license_keeps_the_ttl(self):
        client = _client(_schema(("timelineEventAdd",)))
        client.handlers["OpenCTIEnterpriseEdition"] = graphql_error("ForbiddenAccess")
        self.assertEqual(self._detector(client).snapshot()["ttl"], 3600)


if __name__ == "__main__":
    unittest.main()
