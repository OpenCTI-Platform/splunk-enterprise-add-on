"""Tests for the deployment reconciliation (#68)."""
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from program_fakes import FakeClient, FakeDetector, FakeKV, FakeLogger

from deployment_reporter import STATUS_DEPLOYED, STATUS_EXPIRED, STATUS_REMOVED
from opencti_features import FEATURE_DEPLOYED_ON
from reconciliation import (
    ACTION_DEPLOY,
    ACTION_EXPIRE,
    ACTION_NONE,
    ACTION_REFRESH,
    ACTION_REMOVE,
    ACTION_WAIT,
    Reconciler,
    plan_reconciliation,
    recently_confirmed,
)

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
PLATFORM = {"id": "platform-internal", "standard_id": "identity--p"}


class FakeReporter:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.reports = []
        self.stats = {"sent": 0}
        self.drained = 0

    def report(self, indicator_id, status, external_id=None, removed_at=None, **kwargs):
        self.reports.append((indicator_id, status, external_id, removed_at))
        return True

    def drain(self):
        self.drained += 1


class PlanTest(unittest.TestCase):
    def test_drift_cases(self):
        splunk = {
            "indicator--new": {"_key": "k1"},
            "indicator--sync": {"_key": "k2"},
            "indicator--revoked": {"_key": "k3", "revoked": True},
            "indicator--expired": {"_key": "k4", "valid_until": "2026-01-01T00:00:00.000Z"},
            "indicator--gone-both": {"_key": "k5", "revoked": "true"},
        }
        opencti = {
            "indicator--sync": "active",
            "indicator--revoked": "deployed",
            "indicator--expired": "active",
            "indicator--orphan": "deployed",
            "indicator--old": "removed",
        }
        plan = {(i, a, s) for i, a, s, _ in plan_reconciliation(splunk, opencti, now=NOW)}
        self.assertIn(("indicator--new", ACTION_DEPLOY, STATUS_DEPLOYED), plan)
        self.assertIn(("indicator--sync", ACTION_NONE, None), plan)
        self.assertIn(("indicator--revoked", ACTION_REMOVE, STATUS_REMOVED), plan)
        self.assertIn(("indicator--expired", ACTION_EXPIRE, STATUS_EXPIRED), plan)
        self.assertIn(("indicator--gone-both", ACTION_NONE, None), plan)
        self.assertIn(("indicator--orphan", ACTION_REMOVE, STATUS_REMOVED), plan)
        self.assertNotIn("indicator--old", {i for i, _, _ in plan})

    def test_empty_splunk_collection_never_withdraws_every_deployment(self):
        self.assertEqual(plan_reconciliation({}, {"indicator--a": "deployed", "indicator--b": "active"}, now=NOW), [])

    def test_recently_confirmed_orphan_waits_for_the_lookup(self):
        splunk = {"indicator--held": {"_key": "k1"}}
        opencti = {"indicator--new": "deployed", "indicator--old": "deployed"}
        plan = {(i, a, s) for i, a, s, _ in plan_reconciliation(splunk, opencti, now=NOW, recent={"indicator--new"})}
        self.assertIn(("indicator--new", ACTION_WAIT, None), plan)
        self.assertIn(("indicator--old", ACTION_REMOVE, STATUS_REMOVED), plan)

    def test_recently_confirmed(self):
        confirmed = {
            "indicator--5m": "2026-10-03T11:55:00.000Z",
            "indicator--2h": "2026-10-03T10:00:00.000Z",
            "indicator--skew": "2026-10-03T12:02:00.000Z",
            "indicator--future": "2026-10-04T12:00:00.000Z",
            "indicator--corrupt": "soon",
        }
        self.assertEqual(recently_confirmed(confirmed, NOW), {"indicator--5m", "indicator--skew"})

    def test_refresh(self):
        plan = plan_reconciliation({"indicator--sync": {}}, {"indicator--sync": "active"}, refresh=True, now=NOW)
        self.assertEqual(plan[0][1:3], (ACTION_REFRESH, STATUS_DEPLOYED))


class ReconcilerTest(unittest.TestCase):
    def _deployments(self, pages):
        responses = iter(pages)

        def handler(variables):
            return next(responses)
        return handler

    def test_reconcile_pages_and_reports(self):
        page1 = {"stixCoreRelationships": {"pageInfo": {"hasNextPage": True, "endCursor": "c1"}, "edges": [
            {"node": {"deployment_status": "deployed", "from": {"standard_id": "indicator--orphan"}}}]}}
        page2 = {"stixCoreRelationships": {"pageInfo": {"hasNextPage": False}, "edges": [
            {"node": {"deployment_status": "active", "from": {"standard_id": "indicator--sync"}}}]}}
        client = FakeClient({"SplunkPlatformDeployments": self._deployments([page1, page2])})
        kv = FakeKV([{"_key": "k1", "id": "indicator--new"}, {"_key": "k2", "id": "indicator--sync"}])
        reporter = FakeReporter()
        rows = Reconciler(client, FakeDetector((FEATURE_DEPLOYED_ON,)), PLATFORM, kv, reporter, logger=FakeLogger()).reconcile()
        self.assertEqual(client.calls_of("SplunkPlatformDeployments")[1]["after"], "c1")
        self.assertIn(("indicator--new", STATUS_DEPLOYED, "kvstore:opencti_indicators/k1", None), reporter.reports)
        self.assertIn(("indicator--orphan", STATUS_REMOVED, None, None), reporter.reports)
        self.assertEqual(reporter.drained, 1, "the final flush retries transient failures before exit")
        summary = rows[-1]
        self.assertEqual((summary["splunk_indicators"], summary["opencti_deployments"]), (2, 2))

    def test_reconcile_waits_for_the_lookup_of_a_recently_confirmed_deployment(self):
        """Index mode: an indicator indexed minutes ago is not in opencti_indicators yet."""
        now = datetime.now(timezone.utc)
        page = {"stixCoreRelationships": {"pageInfo": {"hasNextPage": False}, "edges": [
            {"node": {"deployment_status": "deployed", "last_sync_at": (now - timedelta(minutes=5)).isoformat(),
                      "from": {"standard_id": "indicator--indexed"}}},
            {"node": {"deployment_status": "deployed", "last_sync_at": (now - timedelta(hours=2)).isoformat(),
                      "from": {"standard_id": "indicator--gone"}}}]}}
        client = FakeClient({"SplunkPlatformDeployments": page})
        kv = FakeKV([{"_key": "k1", "id": "indicator--held"}])
        reporter = FakeReporter()
        rows = Reconciler(client, FakeDetector((FEATURE_DEPLOYED_ON,)), PLATFORM, kv, reporter, logger=FakeLogger()).reconcile()
        self.assertEqual([r[0] for r in reporter.reports if r[1] == STATUS_REMOVED], ["indicator--gone"])
        self.assertNotIn("indicator--indexed", {r[0] for r in reporter.reports})
        self.assertEqual(rows[-1]["count_wait"], 1)

    def test_reconcile_never_withdraws_on_a_truncated_scan(self):
        page = {"stixCoreRelationships": {"pageInfo": {"hasNextPage": False}, "edges": [
            {"node": {"deployment_status": "deployed", "from": {"standard_id": "indicator--b"}}}]}}
        client = FakeClient({"SplunkPlatformDeployments": page})
        kv = FakeKV([{"_key": "k1", "id": "indicator--a"}, {"_key": "k2", "id": "indicator--b"}])
        reporter = FakeReporter()
        logger = FakeLogger()
        with mock.patch("reconciliation.MAX_INDICATORS", 1):
            Reconciler(client, FakeDetector((FEATURE_DEPLOYED_ON,)), PLATFORM, kv, reporter, logger=logger).reconcile()
        self.assertEqual([r[0] for r in reporter.reports], ["indicator--a"])
        self.assertTrue(any(level == "warning" and "more than 1 entries" in message for level, message in logger.lines))

    def test_truncated_scan_plans_no_orphan_removal(self):
        plan = plan_reconciliation({"indicator--a": {}}, {"indicator--b": "deployed"}, now=NOW, complete=False)
        self.assertEqual([(i, a) for i, a, _, _ in plan], [("indicator--a", ACTION_DEPLOY)])

    def test_reconcile_keeps_the_external_id_opencti_holds(self):
        """An index-mode deployment keeps its index external id instead of flapping to the KV key."""
        index_id = "index:opencti/indicator--revoked"
        page = {"stixCoreRelationships": {"pageInfo": {"hasNextPage": False}, "edges": [
            {"node": {"deployment_status": "deployed", "external_id": index_id,
                      "from": {"standard_id": "indicator--revoked"}}},
            {"node": {"deployment_status": "deployed", "external_id": "index:opencti/indicator--gone",
                      "from": {"standard_id": "indicator--gone"}}}]}}
        client = FakeClient({"SplunkPlatformDeployments": page})
        kv = FakeKV([{"_key": "indicator--revoked", "id": "indicator--revoked", "revoked": True}])
        reporter = FakeReporter()
        Reconciler(client, FakeDetector((FEATURE_DEPLOYED_ON,)), PLATFORM, kv, reporter, logger=FakeLogger()).reconcile()
        self.assertIn(("indicator--revoked", STATUS_REMOVED, index_id, None), reporter.reports)
        self.assertIn(("indicator--gone", STATUS_REMOVED, "index:opencti/indicator--gone", None), reporter.reports)

    def test_new_deployment_takes_the_identity_of_the_stream_input(self):
        """Without an external id in OpenCTI: the one the stream input reported, else the lookup's index."""
        from addon_state import state_key

        empty = {"stixCoreRelationships": {"pageInfo": {"hasNextPage": False}, "edges": []}}
        kv = FakeKV([
            {"_key": "indicator--reported", "id": "indicator--reported", "source_index": "main"},
            {"_key": "indicator--indexed", "id": "indicator--indexed", "source_index": "opencti"},
            {"_key": "k3", "id": "indicator--kv"},
        ])
        deployments = FakeKV([{"_key": state_key("indicator--reported"), "indicator_id": "indicator--reported",
                               "external_id": "index:default/indicator--reported"}])
        reporter = FakeReporter()
        Reconciler(FakeClient({"SplunkPlatformDeployments": empty}), FakeDetector((FEATURE_DEPLOYED_ON,)), PLATFORM, kv,
                   reporter, logger=FakeLogger(), deployments=deployments).reconcile()
        external_ids = {indicator_id: external_id for indicator_id, _, external_id, _ in reporter.reports}
        self.assertEqual(external_ids, {
            "indicator--reported": "index:default/indicator--reported",
            "indicator--indexed": "index:opencti/indicator--indexed",
            "indicator--kv": "kvstore:opencti_indicators/k3",
        })

    def test_expired_row_shows_the_status_sent_to_opencti(self):
        page = {"stixCoreRelationships": {"pageInfo": {"hasNextPage": False}, "edges": [
            {"node": {"deployment_status": "deployed", "from": {"standard_id": "indicator--old"}}}]}}
        kv = FakeKV([{"_key": "k1", "id": "indicator--old", "valid_until": "2020-01-01T00:00:00.000Z"}])
        rows = Reconciler(FakeClient({"SplunkPlatformDeployments": page}), FakeDetector((FEATURE_DEPLOYED_ON,)), PLATFORM,
                          kv, FakeReporter(), logger=FakeLogger()).reconcile()
        self.assertEqual((rows[0]["action"], rows[0]["reported_status"]), ("expire", STATUS_REMOVED))

    def test_unreadable_deployment_state_falls_back_to_the_lookup(self):
        empty = {"stixCoreRelationships": {"pageInfo": {"hasNextPage": False}, "edges": []}}
        deployments = FakeKV()

        def unreadable(keys):
            raise RuntimeError("KV down")

        deployments.get_many = unreadable
        reporter = FakeReporter()
        logger = FakeLogger()
        Reconciler(FakeClient({"SplunkPlatformDeployments": empty}), FakeDetector((FEATURE_DEPLOYED_ON,)), PLATFORM,
                   FakeKV([{"_key": "k1", "id": "indicator--a"}]), reporter, logger=logger,
                   deployments=deployments).reconcile()
        self.assertEqual(reporter.reports[0][2], "kvstore:opencti_indicators/k1")
        self.assertTrue(logger.has("warning", "opencti_deployments unreadable"))

    def test_skipped_without_feature_or_platform(self):
        reporter = FakeReporter()
        self.assertEqual(Reconciler(FakeClient(), FakeDetector(), PLATFORM, FakeKV(), reporter).reconcile()[0]["action"], "skipped")
        self.assertEqual(Reconciler(FakeClient(), FakeDetector((FEATURE_DEPLOYED_ON,)), None, FakeKV(), reporter).reconcile()[0]["action"], "skipped")

    def test_skipped_without_a_write_back_mutation(self):
        client = FakeClient()
        rows = Reconciler(client, FakeDetector((FEATURE_DEPLOYED_ON,)), PLATFORM, FakeKV([{"_key": "k1", "id": "indicator--a"}]),
                          FakeReporter(enabled=False)).reconcile()
        self.assertEqual(rows, [{"action": "skipped", "message": "The OpenCTI platform has no deployment write-back mutation"}])
        self.assertEqual(client.calls_of("SplunkPlatformDeployments"), [])


if __name__ == "__main__":
    unittest.main()
