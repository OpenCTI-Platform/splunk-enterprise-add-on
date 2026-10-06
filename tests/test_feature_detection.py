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


def _compute(mutations=(), enterprise=False):
    return compute_features(set(mutations), enterprise)


PROGRAM_MUTATIONS = (
    "investigationRunAdd",
)
PROGRAM_QUERIES = ("about",)
PROBE_SCHEMA = _schema(("investigationRunAdd",), (), ())


def _client(schema, version="7.261003.0", enterprise=True, fail=False):
    def introspection(_):
        return transport_error() if fail else schema

    return FakeClient({
        "OpenCTIFeatureDetection": introspection,
        "OpenCTIVersion": {"about": {"version": version}},
        "OpenCTIEnterpriseEdition": {"settings": {"platform_enterprise_edition": {"license_validated": enterprise}}},
    })


class ComputeFeaturesTest(unittest.TestCase):
    def test_current_release_has_no_program_feature(self):
        self.assertEqual(_compute(mutations={"stixBundlePush", "registerConnector"}), [])

    def test_program_branches_enable_every_feature(self):
        result = _compute(mutations=set(PROGRAM_MUTATIONS), enterprise=True)
        for feature in (features.FEATURE_CASE_AUTOPILOT, features.FEATURE_ENTERPRISE_EDITION):
            self.assertIn(feature, result)

    def test_case_autopilot_requires_enterprise_edition(self):
        self.assertNotIn(features.FEATURE_CASE_AUTOPILOT, _compute({"investigationRunAdd"}))
        self.assertIn(features.FEATURE_CASE_AUTOPILOT, _compute({"investigationRunAdd"}, enterprise=True))


class DetectorTest(unittest.TestCase):
    def setUp(self):
        OpenCTIFeatureDetector.clear_memory()
        self.now = [1000.0]

    def _detector(self, client, cache=None, ttl=3600, logger=None):
        return OpenCTIFeatureDetector(client, logger=logger or FakeLogger(), cache=cache, ttl=ttl, clock=lambda: self.now[0])

    def test_detects_and_caches_in_memory(self):
        client = _client(PROBE_SCHEMA)
        detector = self._detector(client)
        self.assertTrue(detector.has(features.FEATURE_CASE_AUTOPILOT))
        self.assertEqual(detector.version, "7.261003.0")
        detector.has(features.FEATURE_CASE_AUTOPILOT)
        self.assertEqual(len(client.calls_of("OpenCTIFeatureDetection")), 1)

    def test_persistent_cache_is_shared_between_processes(self):
        cache = FakeCache()
        first = _client(PROBE_SCHEMA)
        self._detector(first, cache=cache).snapshot()
        OpenCTIFeatureDetector.clear_memory()  # new process
        second = _client(_schema())
        self.assertTrue(self._detector(second, cache=cache).has(features.FEATURE_CASE_AUTOPILOT))
        self.assertEqual(second.calls, [])

    def test_corrupt_persistent_entries_are_detected_again(self):
        for corrupt in (
            {"features": "not json", "detected_at": 1000.0},
            {"features": '{"case_autopilot": true}', "detected_at": 1000.0},
            {"features": "[]", "detected_at": "yesterday"},
            {"features": "[]", "detected_at": 1000.0, "ttl": "soon"},
            {"features": "[]", "detected_at": "nan"},
            # detector clock: 1000.0; a millisecond timestamp lies far in the future
            {"features": "[]", "detected_at": 1000.0 * 1000},
            {"features": "[]", "detected_at": 1000.0 - 7200, "ttl": 10 ** 9},
        ):
            with self.subTest(corrupt=corrupt):
                OpenCTIFeatureDetector.clear_memory()
                client = _client(PROBE_SCHEMA)
                cache = FakeCache()
                detector = self._detector(client, cache=cache)
                cache.set(detector.cache_key, corrupt)
                self.assertTrue(detector.has(features.FEATURE_CASE_AUTOPILOT))
                self.assertEqual(len(client.calls_of("OpenCTIFeatureDetection")), 1)

    def test_detection_time_within_the_clock_skew_of_another_search_head_is_fresh(self):
        cache = FakeCache()
        client = _client(_schema())
        detector = self._detector(client, cache=cache)
        cache.set(detector.cache_key, {"features": '["case_autopilot"]', "detected_at": self.now[0] + 120})
        self.assertTrue(detector.has(features.FEATURE_CASE_AUTOPILOT))
        self.assertEqual(client.calls, [])

    def test_cache_expires_after_ttl(self):
        client = _client(PROBE_SCHEMA)
        detector = self._detector(client, ttl=60)
        detector.snapshot()
        self.now[0] += 61
        detector.snapshot()
        self.assertEqual(len(client.calls_of("OpenCTIFeatureDetection")), 2)

    def test_failure_disables_features_and_retries_soon(self):
        cache = FakeCache()
        client = _client(PROBE_SCHEMA, fail=True)
        logger = FakeLogger()
        detector = self._detector(client, cache=cache, logger=logger)
        self.assertFalse(detector.has(features.FEATURE_CASE_AUTOPILOT))
        self.assertTrue(detector.snapshot().get("failed"))
        self.assertTrue(logger.has("warning", "feature detection failed"))
        self.assertEqual(cache.values, {}, "a failed detection is never persisted")
        self.now[0] += features.FAILURE_TTL_SECONDS + 1
        detector.snapshot()
        self.assertEqual(len(client.calls_of("OpenCTIFeatureDetection")), 2)

    def test_require_logs_once_per_action(self):
        logger = FakeLogger()
        detector = self._detector(_client(_schema()), logger=logger)
        self.assertFalse(detector.require(features.FEATURE_CASE_AUTOPILOT, "Run Case Autopilot"))
        self.assertFalse(detector.require(features.FEATURE_CASE_AUTOPILOT, "Run Case Autopilot"))
        skipped = [line for level, line in logger.lines if "Run Case Autopilot: skipped" in line]
        self.assertEqual(len(skipped), 1)
        self.assertIn("Case Autopilot", skipped[0])

    def test_version_and_license_errors_do_not_break_detection(self):
        client = _client(PROBE_SCHEMA)
        client.handlers["OpenCTIVersion"] = transport_error("forbidden")
        client.handlers["OpenCTIEnterpriseEdition"] = transport_error("forbidden")
        detector = self._detector(client)
        self.assertFalse(detector.has(features.FEATURE_CASE_AUTOPILOT), "the license is unknown")
        self.assertEqual(detector.version, "unknown")
        self.assertFalse(detector.has(features.FEATURE_ENTERPRISE_EDITION))

    def test_transient_secondary_failure_is_retried_soon(self):
        schema = _schema(PROGRAM_MUTATIONS, PROGRAM_QUERIES)
        for handler in ("OpenCTIEnterpriseEdition",):
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
        client = _client(PROBE_SCHEMA)
        client.handlers["OpenCTIEnterpriseEdition"] = graphql_error("ForbiddenAccess")
        self.assertEqual(self._detector(client).snapshot()["ttl"], 3600)


if __name__ == "__main__":
    unittest.main()
