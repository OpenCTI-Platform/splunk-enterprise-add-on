"""Tests for the telemetry inventory (provides) and its search command (defense matrix, #68)."""
import unittest
from types import SimpleNamespace
from unittest import mock

from program_fakes import FakeCache, FakeClient, FakeDetector, FakeKV, FakeLogger, graphql_error

import openctiprovides
from addon_config import AddonSettings
from addon_state import state_key
from opencti_features import FEATURE_PROVIDES
from provides import (STATUS_DECLARED, STATUS_ERROR, STATUS_PRUNED, STATUS_UNMATCHED, ProvidesPublisher, RateLimiter,
                      aggregate_inventory, provides_description)

PLATFORM = {"id": "platform-internal", "standard_id": "identity--p"}


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
        self.assertEqual(len(state.records), 3)
        unmatched = [r for r in state.records.values() if r["data_component"] == "Unknown Thing"][0]
        self.assertEqual((unmatched["status"], unmatched["message"]),
                         (STATUS_UNMATCHED, "no Data Component with this name in OpenCTI"))
        self.assertEqual(unmatched.get("relationship_ids", ""), "")

    def test_failed_declaration_is_kept_for_monitoring(self):
        client = FakeClient({"SplunkDataComponents": self._dc, "SplunkProvides": graphql_error("denied")})
        state = FakeKV([{"_key": state_key("platform-internal", "network traffic flow"), "platform_id": "platform-internal",
                         "data_component": "Network Traffic Flow", "relationship_ids": "rel-2", "status": STATUS_DECLARED}])
        ProvidesPublisher(client, FakeDetector((FEATURE_PROVIDES,)), PLATFORM, state, logger=FakeLogger()).publish(
            self.INVENTORY[:2])
        new = state.records[state_key("platform-internal", "process creation")]
        self.assertEqual(new["status"], STATUS_ERROR)
        self.assertIn("denied", new["message"])
        earlier = state.records[state_key("platform-internal", "network traffic flow")]
        self.assertEqual((earlier["status"], earlier["relationship_ids"]), (STATUS_DECLARED, "rel-2"),
                         "an earlier declaration stays prunable")
        self.assertIn("denied", earlier["message"])

    def test_relationships_created_before_a_failure_stay_prunable(self):
        def two_components(variables):
            return {"dataComponents": {"edges": [{"node": {"id": "dc-1", "name": "Process Creation"}},
                                                 {"node": {"id": "dc-1b", "name": "Process Creation"}}]}}

        client = FakeClient({"SplunkDataComponents": two_components,
                             "SplunkProvides": lambda v: graphql_error("denied") if v["input"]["toId"] == "dc-1b"
                             else {"stixCoreRelationshipAdd": {"id": "rel-1"}}})
        state = FakeKV()
        rows = ProvidesPublisher(client, FakeDetector((FEATURE_PROVIDES,)), PLATFORM, state, logger=FakeLogger()).publish(
            self.INVENTORY[:1])
        self.assertEqual(rows[0]["status"], STATUS_ERROR)
        record = state.records[state_key("platform-internal", "process creation")]
        self.assertEqual((record["status"], record["relationship_ids"]), (STATUS_DECLARED, "rel-1"))
        self.assertIn("denied", record["message"])
        self.assertEqual(record["data_component_ids"], "dc-1,dc-1b")

    def test_successful_declaration_clears_the_message(self):
        client = FakeClient({"SplunkDataComponents": self._dc, "SplunkProvides": {"stixCoreRelationshipAdd": {"id": "rel"}}})
        key = state_key("platform-internal", "process creation")
        state = FakeKV([{"_key": key, "platform_id": "platform-internal", "data_component": "Process Creation",
                         "status": STATUS_ERROR, "message": "denied"}])
        ProvidesPublisher(client, FakeDetector((FEATURE_PROVIDES,)), PLATFORM, state).publish(self.INVENTORY[:1])
        self.assertEqual((state.records[key]["status"], state.records[key]["message"]), (STATUS_DECLARED, ""))

    def test_prune_retires_unmatched_entries_of_vanished_telemetry(self):
        client = FakeClient({"SplunkDataComponents": self._dc, "SplunkProvides": {"stixCoreRelationshipAdd": {"id": "rel"}}})
        state = FakeKV([{"_key": "gone", "platform_id": "platform-internal", "data_component": "Unknown Thing",
                         "status": STATUS_UNMATCHED, "message": "no Data Component with this name in OpenCTI"}])
        rows = ProvidesPublisher(client, FakeDetector((FEATURE_PROVIDES,)), PLATFORM, state).publish(self.INVENTORY[:1], prune=True)
        self.assertEqual(state.records["gone"]["status"], STATUS_PRUNED)
        self.assertIn({"data_component": "Unknown Thing", "status": STATUS_PRUNED, "message": ""}, rows)
        self.assertEqual(client.calls_of("SplunkProvidesDelete"), [])

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

    def test_failed_delete_keeps_the_relationship_declared(self):
        client = FakeClient({"SplunkDataComponents": self._dc,
                             "SplunkProvides": {"stixCoreRelationshipAdd": {"id": "rel"}},
                             "SplunkProvidesDelete": lambda v: graphql_error("denied") if v["id"] == "rel-b" else
                             {"stixCoreRelationshipEdit": {"delete": v["id"]}}})
        state = FakeKV([{"_key": "old", "platform_id": "platform-internal", "data_component": "Module Load",
                         "relationship_ids": "rel-a,rel-b", "status": STATUS_DECLARED}])
        rows = ProvidesPublisher(client, FakeDetector((FEATURE_PROVIDES,)), PLATFORM, state).publish(self.INVENTORY[:1], prune=True)
        self.assertIn("not pruned", [r for r in rows if r["data_component"] == "Module Load"][0]["message"])
        self.assertEqual(state.records["old"]["status"], STATUS_DECLARED)
        self.assertEqual(state.records["old"]["relationship_ids"], "rel-b", "only the relationship left is retried")

    def test_unacknowledged_declaration_is_a_failure(self):
        client = FakeClient({"SplunkDataComponents": self._dc, "SplunkProvides": {"stixCoreRelationshipAdd": None}})
        state = FakeKV()
        rows = ProvidesPublisher(client, FakeDetector((FEATURE_PROVIDES,)), PLATFORM, state, logger=FakeLogger()).publish(
            self.INVENTORY[:1])
        self.assertEqual(rows[0]["status"], STATUS_ERROR)
        self.assertIn("no provides relationship", rows[0]["message"])
        record = state.records[state_key("platform-internal", "process creation")]
        self.assertEqual((record["status"], record.get("relationship_ids", "")), (STATUS_ERROR, ""))

    def test_unacknowledged_delete_keeps_the_relationship_declared(self):
        client = FakeClient({"SplunkDataComponents": self._dc,
                             "SplunkProvides": {"stixCoreRelationshipAdd": {"id": "rel"}},
                             "SplunkProvidesDelete": {"stixCoreRelationshipEdit": None}})
        state = FakeKV([{"_key": "old", "platform_id": "platform-internal", "data_component": "Module Load",
                         "relationship_ids": "rel-old", "status": STATUS_DECLARED}])
        rows = ProvidesPublisher(client, FakeDetector((FEATURE_PROVIDES,)), PLATFORM, state).publish(self.INVENTORY[:1], prune=True)
        self.assertIn("did not confirm", [r for r in rows if r["data_component"] == "Module Load"][0]["message"])
        self.assertEqual((state.records["old"]["status"], state.records["old"]["relationship_ids"]),
                         (STATUS_DECLARED, "rel-old"))

    def test_empty_inventory_is_never_pruned(self):
        client = FakeClient({"SplunkDataComponents": self._dc})
        state = FakeKV([{"_key": "old", "platform_id": "platform-internal", "data_component": "Module Load",
                         "relationship_ids": "rel-old", "status": STATUS_DECLARED}])
        ProvidesPublisher(client, FakeDetector((FEATURE_PROVIDES,)), PLATFORM, state).publish([], prune=True)
        self.assertEqual(client.calls_of("SplunkProvidesDelete"), [])
        self.assertEqual(state.records["old"]["status"], STATUS_DECLARED)

    def test_declaration_error_in_an_earlier_chunk_blocks_pruning(self):
        client = FakeClient({"SplunkDataComponents": self._dc, "SplunkProvides": graphql_error("denied")})
        state = FakeKV([{"_key": "old", "platform_id": "platform-internal", "data_component": "Module Load",
                         "relationship_ids": "rel-old", "status": STATUS_DECLARED}])
        publisher = ProvidesPublisher(client, FakeDetector((FEATURE_PROVIDES,)), PLATFORM, state)
        publisher.publish(self.INVENTORY[:1])
        client.handlers["SplunkProvides"] = {"stixCoreRelationshipAdd": {"id": "rel"}}
        publisher.publish(self.INVENTORY[1:2], prune=True, known_keys={self.INVENTORY[0]["data_component"].lower()})
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


class RateLimiterTest(unittest.TestCase):
    def test_bursts_then_waits(self):
        now = [0.0]
        waits = []

        def sleep(seconds):
            waits.append(seconds)
            now[0] += seconds

        limiter = RateLimiter(2, clock=lambda: now[0], sleep=sleep)
        self.assertEqual(limiter.acquire(), 0.0)
        self.assertEqual(limiter.acquire(), 0.0)
        self.assertAlmostEqual(limiter.acquire(), 30.0)
        self.assertEqual(len(waits), 1)


class FakeCommandContext:
    def __init__(self, client=None, features=(), platform=PLATFORM, collections=None):
        self.client = client or FakeClient()
        self.detector = FakeDetector(features)
        self.platform = platform
        self.logger = FakeLogger()
        self.settings = AddonSettings({"opencti_url": "https://opencti.example", "opencti_api_key": "k"}, server_name="sh01")
        self.collections = collections if collections is not None else {}
        self.cache = FakeCache()
        self.invalidated = 0

    def invalidate_platform(self):
        self.invalidated += 1

    def collection(self, name):
        return self.collections.setdefault(name, FakeKV())


class ProvidesCommandTest(unittest.TestCase):
    def test_publishes_rows(self):
        client = FakeClient({
            "SplunkDataComponents": {"dataComponents": {"edges": [{"node": {"id": "dc-1", "name": "Process Creation"}}]}},
            "SplunkProvides": {"stixCoreRelationshipAdd": {"id": "rel"}},
        })
        context = FakeCommandContext(client, (FEATURE_PROVIDES,))
        command = openctiprovides.OpenCTIProvidesCommand()
        command._finished = True
        with mock.patch.object(openctiprovides, "CommandContext", return_value=context):
            rows = list(command.transform([{"data_component": "Process Creation", "sources": "sourcetype:sysmon", "event_count": "9"}]))
        self.assertEqual(rows[0]["status"], "declared")


class CommandContextTest(unittest.TestCase):
    def test_builds_client_detector_and_platform(self):
        import command_common

        settings = AddonSettings({"opencti_url": "https://opencti.example", "opencti_api_key": "k"},
                                 platform={"security_platform_auto_create": "0"})
        command = SimpleNamespace(metadata=SimpleNamespace(searchinfo=SimpleNamespace(session_key="s", splunkd_uri="https://127.0.0.1:8089")))
        with mock.patch.object(command_common, "load_settings", return_value=settings), \
                mock.patch.object(command_common, "connect_service", return_value=mock.Mock()) as connect, \
                mock.patch.object(command_common, "KVStoreCache", side_effect=Exception("no kv")):
            context = command_common.CommandContext(command, "test")
            self.assertEqual(context.client.opencti_url, "https://opencti.example")
            connect.assert_called_once_with("s", "TA-opencti-for-splunk-enterprise", "https://127.0.0.1:8089")
            with mock.patch.object(context.detector, "require", return_value=True), \
                    mock.patch.object(context.detector, "snapshot", return_value={"features": []}):
                self.assertIsNone(context.platform, "auto creation disabled and no id")


class LoadSettingsTest(unittest.TestCase):
    def _load(self, proxy):
        import logging

        import addon_config
        import utils
        from solnlib import conf_manager, splunkenv

        conf = mock.Mock()
        conf.get.side_effect = lambda name: {"account": {"opencti_url": "https://opencti.example/",
                                                         "opencti_api_key": "key"}}.get(name, {})
        manager = mock.Mock()
        manager.get_conf.return_value = conf
        with mock.patch.object(conf_manager, "ConfManager", return_value=manager), \
                mock.patch.object(conf_manager, "get_proxy_dict", **proxy), \
                mock.patch.object(splunkenv, "get_splunk_host_info", return_value=("sh1", "sh1")), \
                mock.patch.object(utils, "get_user_agent", return_value="ua"):
            return addon_config.load_settings("session", logging.getLogger("settings-test"))

    def test_reads_the_proxy_settings(self):
        proxy = {"proxy_enabled": "1", "proxy_url": "proxy.example", "proxy_port": "3128"}
        settings = self._load({"return_value": proxy})
        self.assertEqual(settings.proxy_settings, proxy)
        self.assertEqual(settings.opencti_url, "https://opencti.example")
        self.assertEqual(settings.server_name, "sh1")

    def test_unreadable_proxy_settings_never_connect_directly(self):
        with self.assertRaisesRegex(RuntimeError, "Proxy settings unreadable"):
            self._load({"side_effect": Exception("Failed to fetch 'proxy'")})


if __name__ == "__main__":
    unittest.main()
