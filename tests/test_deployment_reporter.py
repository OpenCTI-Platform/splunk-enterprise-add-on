"""Tests for the deployment write-back (WS-B, #68)."""
import unittest
from datetime import datetime, timezone

from program_fakes import FakeClient, FakeDetector, FakeLogger, graphql_error, transport_error

from deployment_reporter import (
    DeploymentReporter,
    RateLimiter,
    STATUS_DEPLOYED,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_REMOVED,
    removal_status,
)
from opencti_features import FEATURE_DEPLOYMENT, FEATURE_DEPLOYMENT_BATCH

BATCH = "SplunkIndicatorReportDeployments"
ONE = "SplunkIndicatorReportDeployment"
ALL = (FEATURE_DEPLOYMENT, FEATURE_DEPLOYMENT_BATCH)


class Clock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def _batch_ok(variables):
    return {"indicatorReportDeployments": {
        "processed": len(variables["reports"]), "created": len(variables["reports"]), "updated": 0, "unchanged": 0, "errors": [],
    }}


def _reporter(client, features=ALL, batch_size=100, sink=None, clock=None, platform="platform-1"):
    clock = clock or Clock()
    return DeploymentReporter(
        client, FakeDetector(features), platform, batch_size=batch_size, flush_interval=10,
        rate_per_minute=6000, logger=FakeLogger(), state_sink=sink, clock=clock, sleep=clock.sleep,
    )


class RemovalStatusTest(unittest.TestCase):
    NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)

    def test_expired_when_valid_until_passed(self):
        self.assertEqual(removal_status({"valid_until": "2026-10-01T00:00:00.000Z"}, self.NOW), STATUS_EXPIRED)

    def test_removed_otherwise(self):
        self.assertEqual(removal_status({"valid_until": "2027-01-01T00:00:00Z"}, self.NOW), STATUS_REMOVED)
        self.assertEqual(removal_status({}, self.NOW), STATUS_REMOVED)
        self.assertEqual(removal_status({"valid_until": "garbage"}, self.NOW), STATUS_REMOVED)


class RateLimiterTest(unittest.TestCase):
    def test_bursts_then_waits(self):
        clock = Clock()
        limiter = RateLimiter(60, clock=clock, sleep=clock.sleep)
        for _ in range(60):
            self.assertEqual(limiter.acquire(), 0.0)
        self.assertAlmostEqual(limiter.acquire(), 1.0)


class ReporterTest(unittest.TestCase):
    def test_batches_and_deduplicates_per_indicator(self):
        client = FakeClient({BATCH: _batch_ok})
        reporter = _reporter(client)
        reporter.report("indicator--1", STATUS_DEPLOYED, "kvstore:opencti_indicators/k1")
        reporter.report("indicator--2", STATUS_DEPLOYED, "kvstore:opencti_indicators/k2")
        reporter.report("indicator--1", STATUS_REMOVED, "kvstore:opencti_indicators/k1")
        self.assertEqual(client.calls, [], "nothing sent before the batch is full or due")
        self.assertEqual(reporter.flush(), 2)
        reports = client.calls_of(BATCH)[0]["reports"]
        self.assertEqual([(r["indicatorId"], r["status"]) for r in reports],
                         [("indicator--2", STATUS_DEPLOYED), ("indicator--1", STATUS_REMOVED)])
        self.assertEqual(reports[0]["externalId"], "kvstore:opencti_indicators/k2")
        self.assertIn("last_sync_at", reports[0]["metadata"])
        self.assertEqual(client.calls_of(BATCH)[0]["platformId"], "platform-1")

    def test_full_batch_is_sent_immediately(self):
        client = FakeClient({BATCH: _batch_ok})
        reporter = _reporter(client, batch_size=2)
        reporter.report("indicator--1", STATUS_DEPLOYED)
        reporter.report("indicator--2", STATUS_DEPLOYED)
        self.assertEqual(len(client.calls_of(BATCH)), 1)

    def test_flush_if_due(self):
        clock = Clock()
        client = FakeClient({BATCH: _batch_ok})
        reporter = _reporter(client, clock=clock)
        reporter.report("indicator--1", STATUS_DEPLOYED)
        reporter.flush_if_due()
        self.assertEqual(client.calls, [])
        clock.now += 11
        reporter.flush_if_due()
        self.assertEqual(len(client.calls_of(BATCH)), 1)

    def test_single_mutation_without_batch_feature(self):
        client = FakeClient({ONE: {"indicatorReportDeployment": {"id": "rel"}}})
        reporter = _reporter(client, features=(FEATURE_DEPLOYMENT,))
        reporter.report("indicator--1", STATUS_FAILED, error_message="KV Store down")
        reporter.flush()
        call = client.calls_of(ONE)[0]
        self.assertEqual(call["status"], STATUS_FAILED)
        self.assertEqual(call["metadata"]["error_message"], "KV Store down")

    def test_batch_mutation_alone_enables_the_write_back(self):
        client = FakeClient({BATCH: {"indicatorReportDeployments": {"created": 1, "errors": []}}})
        reporter = _reporter(client, features=(FEATURE_DEPLOYMENT_BATCH,))
        self.assertTrue(reporter.report("indicator--1", STATUS_DEPLOYED))
        self.assertEqual(reporter.flush(), 1)
        self.assertEqual(len(client.calls_of(BATCH)), 1)

    def test_disabled_on_platforms_without_write_back(self):
        client = FakeClient()
        reporter = _reporter(client, features=())
        self.assertFalse(reporter.report("indicator--1", STATUS_DEPLOYED))
        self.assertEqual(reporter.flush(), 0)
        self.assertEqual(client.calls, [])

    def test_disabled_without_platform(self):
        reporter = _reporter(FakeClient(), platform=lambda: None)
        self.assertFalse(reporter.report("indicator--1", STATUS_DEPLOYED))

    def test_expiry_is_reported_as_a_removal_at_valid_until(self):
        # OpenCTI reserves "expired" to removals no consumer confirmed
        client = FakeClient({BATCH: _batch_ok})
        reporter = _reporter(client)
        reporter.report("indicator--1", STATUS_EXPIRED, removed_at="2026-10-01T00:00:00.000Z")
        reporter.flush()
        [sent] = client.calls_of(BATCH)[0]["reports"]
        self.assertEqual(sent["status"], STATUS_REMOVED)
        self.assertEqual(sent["metadata"]["removed_at"], "2026-10-01T00:00:00.000Z")

    def test_expiry_through_the_single_mutation(self):
        client = FakeClient({ONE: {"indicatorReportDeployment": {"id": "rel"}}})
        reporter = _reporter(client, features=(FEATURE_DEPLOYMENT,))
        reporter.report("indicator--1", STATUS_EXPIRED)
        reporter.flush()
        self.assertEqual([c["status"] for c in client.calls_of(ONE)], [STATUS_REMOVED])

    def test_transport_failure_backs_off_then_drops_after_three_attempts(self):
        clock = Clock()
        records = []
        client = FakeClient({BATCH: transport_error()})
        reporter = _reporter(client, clock=clock, sink=records.extend)
        reporter.report("indicator--1", STATUS_DEPLOYED)
        reporter.flush()
        self.assertIn("indicator--1", reporter.pending)
        self.assertEqual(reporter.flush(), 0, "backoff: nothing is retried right away")
        self.assertEqual(len(client.calls_of(BATCH)), 1)
        clock.now += 16
        reporter.flush()
        clock.now += 61
        reporter.flush()
        self.assertEqual(len(client.calls_of(BATCH)), 3)
        self.assertNotIn("indicator--1", reporter.pending)
        self.assertEqual(records[-1]["result"], "error")
        self.assertEqual(reporter.stats["errors"], 1)

    def test_final_flush_ignores_backoff(self):
        clock = Clock()
        client = FakeClient({BATCH: transport_error()})
        reporter = _reporter(client, clock=clock)
        reporter.report("indicator--1", STATUS_DEPLOYED)
        reporter.flush()
        client.handlers[BATCH] = _batch_ok
        self.assertEqual(reporter.flush(force=True), 1)

    def test_unknown_platform_resolves_it_again_and_retries(self):
        clock = Clock()
        platforms = ["platform-deleted"]
        invalidated = []
        client = FakeClient({ONE: graphql_error("Security platform not found or not accessible")})
        reporter = DeploymentReporter(
            client, FakeDetector((FEATURE_DEPLOYMENT,)), lambda: platforms[0], rate_per_minute=6000,
            logger=FakeLogger(), clock=clock, sleep=clock.sleep, on_platform_missing=lambda: invalidated.append(1),
        )
        reporter.report("indicator--1", STATUS_DEPLOYED)
        reporter.flush()
        self.assertEqual(invalidated, [1])
        self.assertIn("indicator--1", reporter.pending, "the report is kept for the re-resolved platform")
        platforms[0] = "platform-new"
        client.handlers[ONE] = {"indicatorReportDeployment": {"id": "rel"}}
        clock.now += 16
        self.assertEqual(reporter.flush(), 1)
        self.assertEqual(client.calls_of(ONE)[-1]["platformId"], "platform-new")

    def test_unknown_platform_in_batch_mode_invalidates(self):
        invalidated = []
        client = FakeClient({BATCH: graphql_error("Security platform not found or not accessible")})
        reporter = _reporter(client)
        reporter.on_platform_missing = lambda: invalidated.append(1)
        reporter.report("indicator--1", STATUS_DEPLOYED)
        reporter.flush()
        self.assertEqual(invalidated, [1])
        self.assertIn("indicator--1", reporter.pending)

    def test_rejected_reports_are_recorded_not_retried(self):
        records = []

        def batch(variables):
            return {"indicatorReportDeployments": {"processed": 1, "created": 0, "updated": 0, "unchanged": 0,
                                                    "errors": [{"indicatorId": "indicator--1", "message": "Indicator not found"}]}}

        client = FakeClient({BATCH: batch})
        reporter = _reporter(client, sink=records.extend)
        reporter.report("indicator--1", STATUS_DEPLOYED)
        reporter.flush()
        self.assertEqual(reporter.pending, {})
        self.assertEqual(records[0]["error"], "Indicator not found")

    def test_state_records(self):
        records = []
        client = FakeClient({BATCH: _batch_ok})
        reporter = _reporter(client, sink=records.extend)
        reporter.report("indicator--1", STATUS_DEPLOYED, "kvstore:opencti_indicators/k1")
        reporter.flush()
        self.assertEqual(records[0]["indicator_id"], "indicator--1")
        self.assertEqual(records[0]["result"], "ok")
        self.assertEqual(records[0]["external_id"], "kvstore:opencti_indicators/k1")

    def test_queue_is_bounded(self):
        import deployment_reporter

        client = FakeClient({BATCH: transport_error()})
        reporter = _reporter(client, batch_size=500)
        reporter.retry_after = 1e12
        original = deployment_reporter.MAX_PENDING
        deployment_reporter.MAX_PENDING = 3
        try:
            for index in range(5):
                reporter.report(f"indicator--{index}", STATUS_DEPLOYED)
        finally:
            deployment_reporter.MAX_PENDING = original
        self.assertEqual(list(reporter.pending), ["indicator--2", "indicator--3", "indicator--4"])
        self.assertEqual(reporter.stats["dropped"], 2)

    def test_long_values_are_truncated_to_the_server_limits(self):
        client = FakeClient({ONE: {"indicatorReportDeployment": {"id": "rel"}}})
        reporter = _reporter(client, features=(FEATURE_DEPLOYMENT,))
        reporter.report("indicator--1", STATUS_FAILED, "x" * 2000, error_message="e" * 6000)
        reporter.flush()
        call = client.calls_of(ONE)[0]
        self.assertEqual(len(call["externalId"]), 1000)
        self.assertEqual(len(call["metadata"]["error_message"]), 5000)


if __name__ == "__main__":
    unittest.main()
