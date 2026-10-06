"""Tests for OpenCTIFeatureDetector (schema feature detection, #68)."""
import unittest

from program_fakes import FakeCache, FakeClient, FakeLogger, transport_error

import opencti_features as features
from opencti_features import OpenCTIFeatureDetector, compute_features


def _schema(mutations=(), queries=(), indicator=()):
    return {
        "mutationType": {"fields": [{"name": n} for n in mutations]},
        "queryType": {"fields": [{"name": n} for n in queries]},
        "indicatorType": {"fields": [{"name": n} for n in indicator]},
    }


def _compute(mutations=(), queries=()):
    return compute_features(set(mutations), set(queries))


PROGRAM_MUTATIONS = (
    "securityPlatformAdd", "huntRunEvidenceAdd",
)
PROGRAM_QUERIES = ("securityPlatforms", "huntRun", "about")
PROBE_SCHEMA = _schema(("huntRunEvidenceAdd",), (), ())


def _client(schema, version="7.261003.0", fail=False):
    def introspection(_):
        return transport_error() if fail else schema

    return FakeClient({
        "OpenCTIFeatureDetection": introspection,
        "OpenCTIVersion": {"about": {"version": version}},
    })


class ComputeFeaturesTest(unittest.TestCase):
    def test_current_release_has_no_program_feature(self):
        self.assertEqual(_compute({"stixBundlePush", "registerConnector"}, {"indicator"}), [])

    def test_security_platform_needs_add_and_list(self):
        self.assertIn(features.FEATURE_SECURITY_PLATFORM, _compute({"securityPlatformAdd"}, {"securityPlatforms"}))
        self.assertNotIn(features.FEATURE_SECURITY_PLATFORM, _compute({"securityPlatformAdd"}))

    def test_program_branches_enable_every_feature(self):
        result = _compute(set(PROGRAM_MUTATIONS), set(PROGRAM_QUERIES))
        for feature in (features.FEATURE_SECURITY_PLATFORM, features.FEATURE_HUNTS, features.FEATURE_HUNT_EVIDENCE):
            self.assertIn(feature, result)


class DetectorTest(unittest.TestCase):
    def setUp(self):
        OpenCTIFeatureDetector.clear_memory()
        self.now = [1000.0]

    def _detector(self, client, cache=None, ttl=3600, logger=None):
        return OpenCTIFeatureDetector(client, logger=logger or FakeLogger(), cache=cache, ttl=ttl, clock=lambda: self.now[0])

    def test_detects_and_caches_in_memory(self):
        client = _client(PROBE_SCHEMA)
        detector = self._detector(client)
        self.assertTrue(detector.has(features.FEATURE_HUNT_EVIDENCE))
        self.assertEqual(detector.version, "7.261003.0")
        detector.has(features.FEATURE_HUNT_EVIDENCE)
        self.assertEqual(len(client.calls_of("OpenCTIFeatureDetection")), 1)

    def test_persistent_cache_is_shared_between_processes(self):
        cache = FakeCache()
        first = _client(PROBE_SCHEMA)
        self._detector(first, cache=cache).snapshot()
        OpenCTIFeatureDetector.clear_memory()  # new process
        second = _client(_schema())
        self.assertTrue(self._detector(second, cache=cache).has(features.FEATURE_HUNT_EVIDENCE))
        self.assertEqual(second.calls, [])

    def test_corrupt_persistent_entries_are_detected_again(self):
        for corrupt in (
            {"features": "not json", "detected_at": 1000.0},
            {"features": '{"hunt_evidence": true}', "detected_at": 1000.0},
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
                self.assertTrue(detector.has(features.FEATURE_HUNT_EVIDENCE))
                self.assertEqual(len(client.calls_of("OpenCTIFeatureDetection")), 1)

    def test_detection_time_within_the_clock_skew_of_another_search_head_is_fresh(self):
        cache = FakeCache()
        client = _client(_schema())
        detector = self._detector(client, cache=cache)
        cache.set(detector.cache_key, {"features": '["hunt_evidence"]', "detected_at": self.now[0] + 120})
        self.assertTrue(detector.has(features.FEATURE_HUNT_EVIDENCE))
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
        self.assertFalse(detector.has(features.FEATURE_HUNT_EVIDENCE))
        self.assertTrue(detector.snapshot().get("failed"))
        self.assertTrue(logger.has("warning", "feature detection failed"))
        self.assertEqual(cache.values, {}, "a failed detection is never persisted")
        self.now[0] += features.FAILURE_TTL_SECONDS + 1
        detector.snapshot()
        self.assertEqual(len(client.calls_of("OpenCTIFeatureDetection")), 2)

    def test_require_logs_once_per_action(self):
        logger = FakeLogger()
        detector = self._detector(_client(_schema()), logger=logger)
        self.assertFalse(detector.require(features.FEATURE_HUNT_EVIDENCE, "Hunt evidence attachment to the run"))
        self.assertFalse(detector.require(features.FEATURE_HUNT_EVIDENCE, "Hunt evidence attachment to the run"))
        skipped = [line for level, line in logger.lines if "Hunt evidence attachment to the run: skipped" in line]
        self.assertEqual(len(skipped), 1)
        self.assertIn("hunt evidence write-back", skipped[0])

    def test_version_error_does_not_break_detection(self):
        client = _client(PROBE_SCHEMA)
        client.handlers["OpenCTIVersion"] = transport_error("forbidden")
        detector = self._detector(client)
        self.assertTrue(detector.has(features.FEATURE_HUNT_EVIDENCE))
        self.assertEqual(detector.version, "unknown")


if __name__ == "__main__":
    unittest.main()
