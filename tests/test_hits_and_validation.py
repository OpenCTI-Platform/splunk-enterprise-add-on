"""Tests for hit reporting and the IOC validation proof (WS-C, #68)."""
import json
import unittest
from datetime import datetime, timedelta, timezone

from program_fakes import FakeClient, FakeDetector, FakeKV, FakeLogger, graphql_error

from addon_state import state_key
from hits import (
    HitReporter,
    STATUS_DUPLICATE,
    STATUS_ERROR,
    STATUS_INVALID,
    STATUS_NO_PLATFORM,
    STATUS_REPORTED,
    STATUS_REPORTED_AS_SIGHTING,
    is_replay,
    load_windows,
    merge_hit_history,
    parse_hit_row,
)
from opencti_features import (
    FEATURE_HITS,
    FEATURE_IOC_VALIDATION,
    FEATURE_IOC_VALIDATION_RESULTS,
    FEATURE_SECURITY_PLATFORM,
)
from validation import (
    OUTCOME_DETECTED,
    OUTCOME_MISSED,
    OUTCOME_PENDING,
    ValidationProver,
    decide_outcome,
    validation_window,
)

PLATFORM = {"id": "platform-internal", "standard_id": "identity--5b1fb3f9-2d4e-5f2c-9c6a-1d0f1e2f3a4b"}
IND = "indicator--51b92778-cef0-4a90-b7ec-ebd620d01ac9"
ROW = {"indicator_id": IND, "hit_count": "5", "first_hit": "1727000000", "last_hit": "1727000600", "value": "evil.example"}


class HitRowTest(unittest.TestCase):
    def test_parse(self):
        row = parse_hit_row(ROW)
        self.assertEqual((row.count, row.first_hit, row.last_hit), (5, 1727000000.0, 1727000600.0))

    def test_iso_times_and_multivalue_value(self):
        row = parse_hit_row(dict(ROW, first_hit="2024-09-22T10:13:20Z", last_hit="2024-09-22T10:23:20Z", value=["a", "b"]))
        self.assertEqual(row.last_hit - row.first_hit, 600)
        self.assertEqual(row.value, "a")

    def test_invalid_rows(self):
        for bad in ({"indicator_id": "1.2.3.4"}, dict(ROW, hit_count="0"), dict(ROW, hit_count="x"), dict(ROW, last_hit="")):
            with self.assertRaises(ValueError):
                parse_hit_row(bad)

    def test_history_merge_and_replay(self):
        row = parse_hit_row(ROW)
        record = merge_hit_history(None, row, STATUS_REPORTED, "platform-internal")
        self.assertEqual(record["hit_count"], 5)
        self.assertTrue(is_replay(record, row))
        later = parse_hit_row(dict(ROW, first_hit="1727001000", last_hit="1727001500", hit_count="2"))
        self.assertFalse(is_replay(record, later))
        merged = merge_hit_history(record, later, STATUS_REPORTED, "platform-internal")
        self.assertEqual(merged["hit_count"], 7)
        self.assertEqual(len(load_windows(merged)), 2)

    def test_recent_windows_are_bounded(self):
        import hits

        record = None
        for index in range(hits.MAX_RECENT_WINDOWS + 5):
            row = parse_hit_row(dict(ROW, first_hit=str(1727000000 + index * 10), last_hit=str(1727000005 + index * 10)))
            record = merge_hit_history(record, row, STATUS_REPORTED, "p")
        self.assertEqual(len(load_windows(record)), hits.MAX_RECENT_WINDOWS)


class HitReporterTest(unittest.TestCase):
    def _reporter(self, client, features, platform=PLATFORM, history=None):
        return HitReporter(client, FakeDetector(features), platform, history or FakeKV(), logger=FakeLogger())

    def test_reports_through_indicator_report_hits(self):
        client = FakeClient({"SplunkIndicatorHits": {"indicatorReportHits": {"id": "s"}}})
        history = FakeKV()
        reporter = self._reporter(client, (FEATURE_HITS, FEATURE_SECURITY_PLATFORM), history=history)
        self.assertEqual(reporter.report(dict(ROW))["opencti_hit_status"], STATUS_REPORTED)
        call = client.calls_of("SplunkIndicatorHits")[0]
        self.assertEqual((call["indicatorId"], call["platformId"], call["count"]), (IND, "platform-internal", 5))
        self.assertEqual(call["lastHit"], "2024-09-22T10:23:20.000Z")
        self.assertEqual(history.get(state_key(IND))["hit_count"], 5)

    def test_replayed_window_is_not_reported_twice(self):
        client = FakeClient({"SplunkIndicatorHits": {"indicatorReportHits": {"id": "s"}}})
        reporter = self._reporter(client, (FEATURE_HITS,))
        reporter.report(dict(ROW))
        self.assertEqual(reporter.report(dict(ROW))["opencti_hit_status"], STATUS_DUPLICATE)
        self.assertEqual(len(client.calls_of("SplunkIndicatorHits")), 1)

    def test_fallback_sighting_on_platforms_without_hits(self):
        client = FakeClient()
        history = FakeKV()
        reporter = self._reporter(client, (FEATURE_SECURITY_PLATFORM,), history=history)
        self.assertEqual(reporter.report(dict(ROW))["opencti_hit_status"], STATUS_REPORTED_AS_SIGHTING)
        self.assertEqual(history.records, {}, "history is written once the bundle is sent")
        reporter.flush()
        sighting = [o for o in json.loads(client.bundles[0])["objects"] if o["type"] == "sighting"][0]
        self.assertEqual(sighting["sighting_of_ref"], IND)
        self.assertEqual(sighting["where_sighted_refs"], [PLATFORM["standard_id"]])
        self.assertEqual(sighting["count"], 5)
        self.assertFalse(sighting["x_opencti_negative"])
        self.assertEqual(len(history.records), 1)

    def test_fallback_sightings_are_batched(self):
        import hits

        client = FakeClient()
        reporter = self._reporter(client, (FEATURE_SECURITY_PLATFORM,))
        total = hits.SIGHTINGS_PER_BUNDLE + 1
        for index in range(total):
            reporter.report(dict(ROW, indicator_id=f"indicator--{index:08d}-cef0-4a90-b7ec-ebd620d01ac9"))
        self.assertEqual(reporter.flush(), {})
        self.assertEqual(len(client.bundles), 2)
        sightings = [o for b in client.bundles for o in json.loads(b)["objects"] if o["type"] == "sighting"]
        self.assertEqual(len(sightings), total)

    def test_failed_bundle_is_reported_and_not_recorded(self):
        client = FakeClient()

        def fail(bundle):
            raise RuntimeError("bundle rejected")

        client.send_stix_bundle = fail
        history = FakeKV()
        reporter = self._reporter(client, (FEATURE_SECURITY_PLATFORM,), history=history)
        reporter.report(dict(ROW))
        failed = reporter.flush()
        self.assertIn("bundle rejected", failed[IND])
        self.assertEqual(history.records, {})
        self.assertEqual(reporter.report(dict(ROW))["opencti_hit_status"], STATUS_REPORTED_AS_SIGHTING,
                         "a window that was not sent is not a replay")

    def test_replay_inside_one_search_before_flush(self):
        client = FakeClient()
        reporter = self._reporter(client, (FEATURE_SECURITY_PLATFORM,))
        reporter.report(dict(ROW))
        self.assertEqual(reporter.report(dict(ROW))["opencti_hit_status"], STATUS_DUPLICATE)
        reporter.flush()
        self.assertEqual(len(client.bundles), 1)

    def test_no_platform(self):
        reporter = self._reporter(FakeClient(), (FEATURE_HITS,), platform=None)
        self.assertEqual(reporter.report(dict(ROW))["opencti_hit_status"], STATUS_NO_PLATFORM)

    def test_invalid_and_error_rows(self):
        client = FakeClient({"SplunkIndicatorHits": graphql_error("Indicator not found")})
        reporter = self._reporter(client, (FEATURE_HITS,))
        self.assertEqual(reporter.report({"indicator_id": "x"})["opencti_hit_status"], STATUS_INVALID)
        result = reporter.report(dict(ROW))
        self.assertEqual(result["opencti_hit_status"], STATUS_ERROR)
        self.assertIn("Indicator not found", result["opencti_hit_message"])

    def test_custom_field_names(self):
        client = FakeClient({"SplunkIndicatorHits": {"indicatorReportHits": {"id": "s"}}})
        reporter = self._reporter(client, (FEATURE_HITS,))
        row = {"ioc": IND, "n": "3", "t0": "1727000000", "t1": "1727000001"}
        status = reporter.report(row, id_field="ioc", count_field="n", first_field="t0", last_field="t1")
        self.assertEqual(status["opencti_hit_status"], STATUS_REPORTED)


NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


class DecideOutcomeTest(unittest.TestCase):
    def setUp(self):
        self.request = {"status": "completed", "dispatched_at": _iso(NOW - timedelta(hours=2)),
                        "completed_at": _iso(NOW - timedelta(hours=1))}
        self.start, self.end, self.decide_after = validation_window(self.request, 30)

    def test_detected_when_a_hit_overlaps_the_window(self):
        hit = (NOW - timedelta(minutes=90)).timestamp()
        outcome, observed = decide_outcome(self.start, self.end, self.decide_after, [[hit, hit + 5, 1]], 30, NOW)
        self.assertEqual(outcome, OUTCOME_DETECTED)
        self.assertEqual(observed, hit)

    def test_hit_within_the_grace_period_counts(self):
        hit = (NOW - timedelta(minutes=45)).timestamp()
        self.assertEqual(decide_outcome(self.start, self.end, self.decide_after, [[hit, hit, 1]], 30, NOW)[0], OUTCOME_DETECTED)

    def test_hit_before_dispatch_does_not_count(self):
        hit = (NOW - timedelta(hours=5)).timestamp()
        self.assertEqual(decide_outcome(self.start, self.end, self.decide_after, [[hit, hit, 1]], 30, NOW)[0], OUTCOME_MISSED)

    def test_missed_only_after_the_grace_period(self):
        early = self.end + timedelta(minutes=10)
        self.assertEqual(decide_outcome(self.start, self.end, self.decide_after, [], 30, early)[0], OUTCOME_PENDING)
        self.assertEqual(decide_outcome(self.start, self.end, self.decide_after, [], 30, NOW)[0], OUTCOME_MISSED)

    def test_running_request_is_never_missed(self):
        start, end, decide_after = validation_window(dict(self.request, status="running"), 30)
        self.assertIsNone(end)
        self.assertEqual(decide_outcome(start, end, decide_after, [], 30, NOW)[0], OUTCOME_PENDING)
        hit = (NOW - timedelta(minutes=5)).timestamp()
        self.assertEqual(decide_outcome(start, end, decide_after, [[hit, hit, 1]], 30, NOW)[0], OUTCOME_DETECTED)


def _request(status="completed", validation_status="requested", platform=PLATFORM, ioc_value="evil.example"):
    return {
        "id": "request-1",
        "name": "Weekly IOC proof",
        "status": status,
        "created_at": _iso(NOW - timedelta(hours=3)),
        "updated_at": _iso(NOW - timedelta(minutes=30)),
        "dispatched_at": _iso(NOW - timedelta(hours=2)),
        "completed_at": _iso(NOW - timedelta(hours=1)),
        "platforms": [platform],
        "iocs": [{"indicator_id": "ind-internal", "observable_type": "Domain-Name", "value": ioc_value, "test_kind": "dns_resolution"}],
        "deployments": [{
            "id": "dep-1",
            "validation_status": validation_status,
            "validation_run_id": "request-1",
            "from": {"id": "ind-internal", "standard_id": IND},
            "to": platform,
        }],
    }


def _client(requests_nodes, **handlers):
    base = {"SplunkIocValidationRequests": {"iocValidationRequests": {
        "pageInfo": {"hasNextPage": False, "endCursor": None},
        "edges": [{"node": node} for node in requests_nodes],
    }}}
    base.update(handlers)
    return FakeClient(base)


class ValidationProverTest(unittest.TestCase):
    def _prover(self, client, features=(FEATURE_IOC_VALIDATION,), hits=None, results=None, writeback=True):
        return ValidationProver(client, FakeDetector(features), PLATFORM, hits or FakeKV(), results or FakeKV(),
                                grace_minutes=30, writeback=writeback, logger=FakeLogger(), now=NOW)

    def _hits(self, *windows):
        return FakeKV([{"_key": state_key(IND), "indicator_id": IND, "recent_windows": json.dumps(list(windows))}])

    def test_detected_through_the_bundle_fallback(self):
        hit = (NOW - timedelta(minutes=90)).timestamp()
        client = _client([_request()])
        results = FakeKV()
        rows = self._prover(client, hits=self._hits([hit, hit, 2]), results=results).run()
        self.assertEqual(rows[0]["outcome"], OUTCOME_DETECTED)
        self.assertEqual(rows[0]["reported"], "bundle")
        objects = json.loads(client.bundles[0])["objects"]
        relation = [o for o in objects if o["type"] == "relationship"][0]
        self.assertEqual((relation["relationship_type"], relation["source_ref"], relation["target_ref"]),
                         ("deployed-on", IND, PLATFORM["standard_id"]))
        self.assertEqual((relation["validation_status"], relation["validation_run_id"]), ("detected", "request-1"))
        self.assertEqual([o for o in objects if o["type"] == "sighting"], [])
        self.assertTrue(list(results.records.values())[0]["reported"])

    def test_missed_creates_a_negative_sighting(self):
        client = _client([_request()])
        rows = self._prover(client).run()
        self.assertEqual(rows[0]["outcome"], OUTCOME_MISSED)
        sighting = [o for o in json.loads(client.bundles[0])["objects"] if o["type"] == "sighting"][0]
        self.assertTrue(sighting["x_opencti_negative"])
        self.assertEqual(sighting["sighting_of_ref"], IND)
        self.assertEqual(sighting["where_sighted_refs"], [PLATFORM["standard_id"]])

    def test_dedicated_mutation_when_available(self):
        client = _client([_request()], SplunkIocValidationResults={"iocValidationReportResults": {"id": "request-1"}})
        rows = self._prover(client, features=(FEATURE_IOC_VALIDATION, FEATURE_IOC_VALIDATION_RESULTS)).run()
        call = client.calls_of("SplunkIocValidationResults")[0]
        self.assertEqual(call["platformId"], "platform-internal")
        self.assertEqual(call["results"][0]["status"], OUTCOME_MISSED)
        self.assertEqual(client.bundles, [])
        self.assertEqual(rows[0]["reported"], "iocValidationReportResults")

    def test_outcomes_are_reported_once(self):
        client = _client([_request()])
        results = FakeKV()
        self._prover(client, results=results).run()
        rows = self._prover(client, results=results).run()
        self.assertEqual(rows[0]["reported"], "already")
        self.assertEqual(len(client.bundles), 1)

    def test_pairs_already_validated_by_openaev_are_left_alone(self):
        client = _client([_request(validation_status="prevented")])
        self.assertEqual(self._prover(client).run(), [])
        self.assertEqual(client.bundles, [])

    def test_requests_for_other_platforms_are_ignored(self):
        other = {"id": "other", "standard_id": "identity--other"}
        client = _client([_request(platform=other)])
        self.assertEqual(self._prover(client).run(), [])

    def test_pending_outcomes_are_not_reported(self):
        client = _client([_request(status="running")])
        rows = self._prover(client).run()
        self.assertEqual(rows[0]["outcome"], OUTCOME_PENDING)
        self.assertEqual(client.bundles, [])

    def test_writeback_disabled(self):
        client = _client([_request()])
        rows = self._prover(client, writeback=False).run()
        self.assertEqual(rows[0]["outcome"], OUTCOME_MISSED)
        self.assertEqual(client.bundles, [])

    def test_report_failure_keeps_the_pair_for_the_next_run(self):
        client = _client([_request()])

        def failing_bundle(bundle):
            raise graphql_error("worker queue full")

        client.send_stix_bundle = failing_bundle
        results = FakeKV()
        rows = self._prover(client, results=results).run()
        self.assertEqual(rows[0]["reported"], "error")
        self.assertFalse(list(results.records.values())[0]["reported"])

    def test_platform_without_ioc_validation(self):
        client = _client([])
        self.assertEqual(self._prover(client, features=()).run(), [])
        self.assertEqual(client.calls, [])

    def test_old_requests_stop_the_scan(self):
        old = _request()
        old["updated_at"] = _iso(NOW - timedelta(days=40))
        client = _client([old])
        self.assertEqual(self._prover(client).run(), [])


if __name__ == "__main__":
    unittest.main()
