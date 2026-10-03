"""Tests for the deployment reconciliation, knowledge refresh and provides inventory (WS-B, WS-D, WS-E, #68)."""
import unittest
from datetime import datetime, timezone

from program_fakes import FakeClient, FakeDetector, FakeKV, FakeLogger, graphql_error

from deployment_reporter import STATUS_DEPLOYED, STATUS_EXPIRED, STATUS_REMOVED
from opencti_features import FEATURE_DEPLOYED_ON, FEATURE_PROVENANCE, FEATURE_PROVIDES, FEATURE_PULSE
from provides import STATUS_DECLARED, STATUS_PRUNED, STATUS_UNMATCHED, ProvidesPublisher, aggregate_inventory, provides_description
from reconciliation import (
    ACTION_DEPLOY,
    ACTION_EXPIRE,
    ACTION_NONE,
    ACTION_REFRESH,
    ACTION_REMOVE,
    Reconciler,
    plan_reconciliation,
)

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
PLATFORM = {"id": "platform-internal", "standard_id": "identity--p"}


class FakeReporter:
    def __init__(self):
        self.reports = []
        self.stats = {"sent": 0}
        self.flushed = 0

    def report(self, indicator_id, status, external_id=None, removed_at=None, **kwargs):
        self.reports.append((indicator_id, status, external_id, removed_at))
        return True

    def flush(self, force=False):
        self.flushed += 1


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
        self.assertEqual(reporter.flushed, 1)
        summary = rows[-1]
        self.assertEqual((summary["splunk_indicators"], summary["opencti_deployments"]), (2, 2))

    def test_skipped_without_feature_or_platform(self):
        reporter = FakeReporter()
        self.assertEqual(Reconciler(FakeClient(), FakeDetector(), PLATFORM, FakeKV(), reporter).reconcile()[0]["action"], "skipped")
        self.assertEqual(Reconciler(FakeClient(), FakeDetector((FEATURE_DEPLOYED_ON,)), None, FakeKV(), reporter).reconcile()[0]["action"], "skipped")

    def test_knowledge_refresh_updates_changed_records_only(self):
        client = FakeClient({"SplunkIndicatorsKnowledge": {"indicators": {"edges": [
            {"node": {"standard_id": "indicator--a", "corroboration_count": 4, "single_sourced": False,
                      "pulse": {"prevalence": "rare", "trend": "rising"}}},
            {"node": {"standard_id": "indicator--b", "corroboration_count": 1, "single_sourced": True}},
        ]}}})
        kv = FakeKV([
            {"_key": "a", "id": "indicator--a", "value": "1.2.3.4", "corroboration_count": 1, "_user": "nobody"},
            {"_key": "b", "id": "indicator--b", "value": "x", "corroboration_count": 1, "single_sourced": True,
             "has_conflicts": False, "freshness_stale": False},
        ])
        rows = Reconciler(client, FakeDetector((FEATURE_PROVENANCE, FEATURE_PULSE)), PLATFORM, kv, FakeReporter()).refresh_knowledge()
        self.assertEqual(rows[0]["updated"], 1)
        saved = kv.saved[0]
        self.assertEqual((saved["_key"], saved["corroboration_count"], saved["pulse_trend"]), ("a", 4, "rising"))
        self.assertNotIn("_user", saved)
        self.assertEqual(saved["value"], "1.2.3.4", "the whole record is kept")

    def test_knowledge_refresh_skipped_on_older_platforms(self):
        rows = Reconciler(FakeClient(), FakeDetector(), PLATFORM, FakeKV(), FakeReporter()).refresh_knowledge()
        self.assertEqual(rows[0]["action"], "skipped")


class ProvidesTest(unittest.TestCase):
    INVENTORY = [
        {"data_component": "Process Creation", "sources": ["datamodel:Endpoint.Processes", "sourcetype:sysmon"], "event_count": "100"},
        {"data_component": ["Network Traffic Flow", "Unknown Thing"], "sources": "datamodel:Network_Traffic", "event_count": "5"},
        {"data_component": "process creation", "sources": "sourcetype:WinEventLog:Security", "event_count": "1"},
    ]

    def _dc(self, variables):
        names = variables["filters"]["filters"][0]["values"]
        known = {"Process Creation": "dc-1", "Network Traffic Flow": "dc-2"}
        return {"dataComponents": {"edges": [{"node": {"id": known[n], "name": n}} for n in names if n in known]}}

    def test_aggregate(self):
        inventory = aggregate_inventory(self.INVENTORY)
        self.assertEqual(inventory["process creation"]["event_count"], 101)
        self.assertEqual(len(inventory["process creation"]["sources"]), 3)
        self.assertIn("unknown thing", inventory)

    def test_publish(self):
        client = FakeClient({"SplunkDataComponents": self._dc,
                             "SplunkProvides": lambda v: {"stixCoreRelationshipAdd": {"id": "rel-" + v["input"]["toId"]}}})
        state = FakeKV()
        rows = ProvidesPublisher(client, FakeDetector((FEATURE_PROVIDES,)), PLATFORM, state, logger=FakeLogger()).publish(self.INVENTORY)
        statuses = {row["data_component"]: row["status"] for row in rows}
        self.assertEqual(statuses["Process Creation"], STATUS_DECLARED)
        self.assertEqual(statuses["Unknown Thing"], STATUS_UNMATCHED)
        relation = client.calls_of("SplunkProvides")[0]["input"]
        self.assertEqual((relation["fromId"], relation["relationship_type"]), ("platform-internal", "provides"))
        self.assertTrue(relation["description"].startswith("Telemetry available in Splunk from:"))
        self.assertEqual(len(state.records), 2)

    def test_prune_removes_vanished_telemetry(self):
        client = FakeClient({"SplunkDataComponents": self._dc,
                             "SplunkProvides": {"stixCoreRelationshipAdd": {"id": "rel"}},
                             "SplunkProvidesDelete": {"stixCoreRelationshipEdit": {"delete": "rel-old"}}})
        state = FakeKV([{"_key": "old", "platform_id": "platform-internal", "data_component": "Module Load",
                         "relationship_ids": "rel-old", "status": STATUS_DECLARED}])
        rows = ProvidesPublisher(client, FakeDetector((FEATURE_PROVIDES,)), PLATFORM, state).publish(self.INVENTORY[:1], prune=True)
        self.assertIn({"data_component": "Module Load", "status": STATUS_PRUNED, "message": ""}, rows)
        self.assertEqual(client.calls_of("SplunkProvidesDelete"), [{"id": "rel-old"}])
        self.assertEqual(state.records["old"]["status"], STATUS_PRUNED)

    def test_prune_keeps_components_of_previous_chunks(self):
        client = FakeClient({"SplunkDataComponents": self._dc, "SplunkProvides": {"stixCoreRelationshipAdd": {"id": "rel"}}})
        state = FakeKV([{"_key": "old", "platform_id": "platform-internal", "data_component": "Network Traffic Flow",
                         "relationship_ids": "rel-2", "status": STATUS_DECLARED}])
        ProvidesPublisher(client, FakeDetector((FEATURE_PROVIDES,)), PLATFORM, state).publish(
            self.INVENTORY[:1], prune=True, known_keys={"network traffic flow"})
        self.assertEqual(client.calls_of("SplunkProvidesDelete"), [])

    def test_errors_and_absent_feature(self):
        client = FakeClient({"SplunkDataComponents": self._dc, "SplunkProvides": graphql_error("denied")})
        rows = ProvidesPublisher(client, FakeDetector((FEATURE_PROVIDES,)), PLATFORM, FakeKV()).publish(self.INVENTORY[:1])
        self.assertEqual(rows[0]["status"], "error")
        rows = ProvidesPublisher(FakeClient(), FakeDetector(), PLATFORM, FakeKV()).publish(self.INVENTORY)
        self.assertEqual(rows[0]["status"], "skipped")

    def test_description_is_bounded(self):
        description = provides_description([f"s{i}" for i in range(40)])
        self.assertIn("(+25 more)", description)


if __name__ == "__main__":
    unittest.main()
